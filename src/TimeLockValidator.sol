// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IValidator} from "erc7579/interfaces/IERC7579Module.sol";
import {IERC7579Account} from "erc7579/interfaces/IERC7579Account.sol";
import {ModeLib} from "erc7579/lib/ModeLib.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";

interface IERC20Transfer {
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @dev Implemented by BiometricValidator: verifies a WebAuthn assertion made
/// with one of `account`'s enrolled passkeys (the fingerprint registered at
/// signup) over `challenge`. `signature` = abi.encode(WebAuthnSignature).
interface IBiometricVerifier {
    function verifyConfirmation(address account, bytes32 challenge, bytes calldata signature)
        external
        view
        returns (bool);
}

/**
 * @title TimeLockValidator
 * @notice EthosiFi Vault - Core security module with time-locks and biometric bypass
 */
contract TimeLockValidator is IValidator {
    using SignatureCheckerLib for address;

    uint256 constant MODULE_TYPE_VALIDATOR = 1;
    uint256 constant SIG_VALIDATION_SUCCESS = 0;
    uint256 constant SIG_VALIDATION_FAILED = 1;

    uint256 public constant DEFAULT_DELAY = 48 hours;
    uint256 public constant BYPASS_THRESHOLD = 10_000 * 1e6; // $10k USDC

    // ─── Velocity cap (anti drip-drain) ───────────────────────────────────────
    // Per-tx thresholds alone let an attacker with the standard key send an
    // unlimited number of "small" transfers. Every standard-path transfer now
    // also counts against a sliding 24h per-token budget (value AND count).
    // Anything over budget fails validation and must use initiateDelayedTx.
    uint256 public constant VELOCITY_WINDOW = 24 hours;
    uint256 public constant DEFAULT_WINDOW_LIMIT = 2_500 * 1e6; // $2.5k USDC / 24h
    uint256 public constant MAX_TXS_PER_WINDOW = 10;

    /// @dev BiometricValidator used to verify fingerprint confirmations.
    address public immutable biometricVerifier;

    struct TokenPolicy {
        bool set;
        uint128 highValue; // per-tx amount above which a tx must be delayed
        uint128 windowLimit; // max cumulative amount per sliding window
    }

    struct PendingPolicy {
        uint128 highValue;
        uint128 windowLimit;
        uint256 applyAfter;
    }

    struct Velocity {
        uint64 windowStart;
        uint128 curSpent;
        uint128 prevSpent;
        uint32 curCount;
        uint32 prevCount;
    }

    mapping(address => mapping(address => TokenPolicy)) public tokenPolicy; // account => token
    mapping(address => mapping(address => PendingPolicy)) public pendingPolicy;
    mapping(address => mapping(address => Velocity)) public velocity;

    event PolicyChanged(address indexed account, address indexed token, uint256 highValue, uint256 windowLimit);
    event PolicyIncreaseQueued(
        address indexed account, address indexed token, uint256 highValue, uint256 windowLimit, uint256 applyAfter
    );
    event PolicyIncreaseCancelled(address indexed account, address indexed token, address by);

    constructor(address _biometricVerifier) {
        require(_biometricVerifier != address(0), "Zero verifier");
        biometricVerifier = _biometricVerifier;
    }

    struct AccountConfig {
        bool initialized;
        uint256 delay;
        address[] guardians;
        mapping(bytes32 => PendingTx) pending;
        uint256 guardianThreshold;
        uint256 biometricNonce;
        uint256 txNonce;
    }

    struct PendingTx {
        address token;
        uint256 amount;
        address recipient;
        uint256 executeAfter; // creation time (non-zero marker)
        uint256 expiresAt; // fingerprint must confirm before this or the tx is dead
        bool executed;
        bool cancelled;
        uint256 guardianApprovals;
        mapping(address => bool) approved;
    }

    mapping(address => AccountConfig) public accounts;
    mapping(address => bool) public isBiometricKey;

    event TxDelayed(bytes32 indexed txHash, address indexed account, uint256 executeAfter);
    /// @dev Trigger for the off-chain notifier: send the owner an SMS with a
    /// link to confirm this exact transaction with their fingerprint.
    event BiometricConfirmationRequested(
        address indexed account,
        bytes32 indexed txHash,
        address token,
        uint256 amount,
        address recipient,
        uint256 expiresAt
    );
    event TxExpired(bytes32 indexed txHash, address indexed account);
    event TxExecuted(bytes32 indexed txHash);
    event TxCancelled(bytes32 indexed txHash, address indexed guardian);
    event BiometricRegistered(address indexed account);

    function onInstall(bytes calldata data) external {
        // Idempotent: the vault installs this module twice (validator + executor,
        // the executor role is what lets _execute() move delayed funds). The
        // second call must not revert or re-initialise the config.
        if (accounts[msg.sender].initialized) return;

        (address[] memory guardians, uint256 threshold, uint256 customDelay) =
            abi.decode(data, (address[], uint256, uint256));

        AccountConfig storage config = accounts[msg.sender];
        config.initialized = true;
        config.guardians = guardians;
        config.guardianThreshold = threshold;
        config.delay = customDelay > 0 ? customDelay : DEFAULT_DELAY;

        isBiometricKey[msg.sender] = true;
        emit BiometricRegistered(msg.sender);
    }

    function onUninstall(bytes calldata) external {
        delete accounts[msg.sender];
    }

    // [FIXED] IValidator.validateUserOp takes exactly (userOp, userOpHash) — the
    // extra trailing uint256 here didn't match the interface at all, so this
    // function never actually implemented IValidator and the contract failed
    // to compile ("should be marked as abstract").
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        override
        returns (uint256)
    {
        AccountConfig storage config = accounts[msg.sender];
        require(config.initialized, "Not installed");

        // [CRIT FIXED] The old code treated a trailing 0x01 byte on the signature
        // as a "biometric" flag and then ran the SAME signature check, skipping
        // the high-value gate. Anyone able to produce a normal signature could
        // append 0x01 and bypass the time-lock entirely. There is no such path
        // any more: this validator never approves high-value or over-budget
        // transfers. Those go through initiateDelayedTx, or through the
        // separate BiometricValidator (real WebAuthn credential).
        (address token, uint256 amount,) = _decodeCall(userOp.callData);

        if (_isHighValue(msg.sender, token, amount)) return SIG_VALIDATION_FAILED;
        if (!_verifyStandard(msg.sender, userOpHash, userOp.signature)) return SIG_VALIDATION_FAILED;

        // Consume budget only AFTER the signature is valid so forged ops
        // can't burn a victim's quota.
        if (amount > 0 && !_consumeVelocity(msg.sender, token, amount)) return SIG_VALIDATION_FAILED;

        return SIG_VALIDATION_SUCCESS;
    }

    function initiateDelayedTx(address token, uint256 amount, address recipient) external returns (bytes32 txHash) {
        AccountConfig storage config = accounts[msg.sender];
        require(config.initialized, "Not installed");
        // Any transfer may be queued (over-budget small ones must be able to).

        // [HIGH-1 FIXED] Use nonce to prevent hash prediction/front-running
        txHash = keccak256(abi.encodePacked(msg.sender, token, amount, recipient, config.txNonce++));

        PendingTx storage pending = config.pending[txHash];
        require(pending.executeAfter == 0, "Already pending");

        pending.token = token;
        pending.amount = amount;
        pending.recipient = recipient;
        pending.executeAfter = block.timestamp;
        pending.expiresAt = block.timestamp + config.delay; // default 48h

        emit TxDelayed(txHash, msg.sender, pending.expiresAt);
        emit BiometricConfirmationRequested(msg.sender, txHash, token, amount, recipient, pending.expiresAt);
    }

    /// @notice Challenge the owner's authenticator must sign to release `txHash`.
    /// Bound to chain + this contract + account so an assertion can't be reused
    /// for anything else.
    function confirmationChallenge(address account, bytes32 txHash) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), account, txHash));
    }

    /// @notice Release a queued tx using a fingerprint (WebAuthn) assertion from
    /// one of the account's enrolled passkeys. Callable by anyone (the user's
    /// app relays it) — the assertion is the authorization, not msg.sender.
    /// Fails once `expiresAt` has passed: unconfirmed txs are dead after 48h.
    function confirmAndRelease(address account, bytes32 txHash, bytes calldata biometricSig) external {
        PendingTx storage pending = accounts[account].pending[txHash];
        require(pending.executeAfter > 0, "Not found");
        require(!pending.cancelled, "Cancelled");
        require(!pending.executed, "Already executed");
        require(block.timestamp <= pending.expiresAt, "Expired");
        require(
            IBiometricVerifier(biometricVerifier).verifyConfirmation(
                account, confirmationChallenge(account, txHash), biometricSig
            ),
            "Invalid fingerprint"
        );
        _execute(account, txHash);
    }

    /// @notice Mark an unconfirmed tx as expired/cancelled after the window (anyone).
    function expireTx(address account, bytes32 txHash) external {
        PendingTx storage pending = accounts[account].pending[txHash];
        require(pending.executeAfter > 0, "Not found");
        require(!pending.executed && !pending.cancelled, "Finalised");
        require(block.timestamp > pending.expiresAt, "Not expired");
        pending.cancelled = true;
        emit TxExpired(txHash, account);
    }

    /// @notice Cancel a pending tx. The account itself or any guardian may cancel.
    function cancelTx(address account, bytes32 txHash) external {
        require(msg.sender == account || _isGuardian(account, msg.sender), "Not authorized");
        AccountConfig storage config = accounts[account];
        PendingTx storage pending = config.pending[txHash];

        require(pending.executeAfter > 0, "Not found");
        require(!pending.executed, "Already executed");
        require(!pending.cancelled, "Already cancelled");

        pending.cancelled = true;
        emit TxCancelled(txHash, msg.sender);
    }

    function _execute(address account, bytes32 txHash) internal {
        AccountConfig storage config = accounts[account];
        PendingTx storage pending = config.pending[txHash];

        require(!pending.executed, "Already executed");

        // Effects before interaction (reentrancy-safe)
        pending.executed = true;
        emit TxExecuted(txHash);


        address token = pending.token;
        uint256 amount = pending.amount;
        address recipient = pending.recipient;

        // [FIXED] This previously only flagged the pending tx as executed and
        // never actually moved funds — an approved, delay-elapsed transaction
        // could never be released. Calls back into the account as an
        // ERC-7579 executor, matching the executeFromExecutor convention
        // GuardianValidator._executeRecovery already uses in this codebase.
        // NOTE: requires this module to hold executor (not just validator)
        // permission on the account — verify installation grants this before
        // relying on it, and confirm with `forge build`/`forge test` since
        // this environment has no compiler available to check it.
        address target;
        uint256 value;
        bytes memory innerCallData;
        if (token == address(0)) {
            target = recipient;
            value = amount;
            innerCallData = "";
        } else {
            target = token;
            value = 0;
            innerCallData = abi.encodeWithSelector(IERC20Transfer.transfer.selector, recipient, amount);
        }

        IERC7579Account(account).executeFromExecutor(
            ModeLib.encodeSimpleSingle(),
            abi.encodePacked(target, value, innerCallData) // ERC-7579 single exec is PACKED: target(20)||value(32)||data
        );
    }

    function _verifyStandard(address account, bytes32 hash, bytes memory sig) internal view returns (bool) {
        return account.isValidSignatureNow(hash, sig);
    }

    function _isGuardian(address account, address who) internal view returns (bool) {
        address[] storage g = accounts[account].guardians;
        for (uint256 i = 0; i < g.length; i++) {
            if (g[i] == who) return true;
        }
        return false;
    }

    // ─── Per-token policy ─────────────────────────────────────────────────────

    function policyOf(address account, address token) public view returns (uint256 highValue, uint256 windowLimit) {
        TokenPolicy memory p = tokenPolicy[account][token];
        if (p.set) return (p.highValue, p.windowLimit);
        return (BYPASS_THRESHOLD, DEFAULT_WINDOW_LIMIT);
    }

    /// @notice Set per-token limits (raw token units; set ETH via token = address(0)).
    /// Tightening applies immediately. Any loosening is queued for `delay`
    /// and can be cancelled by the account or a guardian, so a stolen key
    /// cannot just raise the cap. Calls to this function from the account fail
    /// the standard validator on purpose (see _decodeCall) and need the
    /// biometric validator.
    function setTokenPolicy(address token, uint128 highValue, uint128 windowLimit) external {
        AccountConfig storage config = accounts[msg.sender];
        require(config.initialized, "Not installed");
        (uint256 curHV, uint256 curWL) = policyOf(msg.sender, token);

        if (highValue <= curHV && windowLimit <= curWL) {
            tokenPolicy[msg.sender][token] = TokenPolicy(true, highValue, windowLimit);
            delete pendingPolicy[msg.sender][token];
            emit PolicyChanged(msg.sender, token, highValue, windowLimit);
        } else {
            uint256 applyAfter = block.timestamp + config.delay;
            pendingPolicy[msg.sender][token] = PendingPolicy(highValue, windowLimit, applyAfter);
            emit PolicyIncreaseQueued(msg.sender, token, highValue, windowLimit, applyAfter);
        }
    }

    function applyPolicy(address account, address token) external {
        PendingPolicy memory p = pendingPolicy[account][token];
        require(p.applyAfter != 0, "Nothing queued");
        require(block.timestamp >= p.applyAfter, "Delay active");
        delete pendingPolicy[account][token];
        tokenPolicy[account][token] = TokenPolicy(true, p.highValue, p.windowLimit);
        emit PolicyChanged(account, token, p.highValue, p.windowLimit);
    }

    function cancelPolicy(address account, address token) external {
        require(msg.sender == account || _isGuardian(account, msg.sender), "Not authorized");
        require(pendingPolicy[account][token].applyAfter != 0, "Nothing queued");
        delete pendingPolicy[account][token];
        emit PolicyIncreaseCancelled(account, token, msg.sender);
    }

    function _isHighValue(address account, address token, uint256 amount) internal view returns (bool) {
        (uint256 highValue,) = policyOf(account, token);
        return amount > highValue;
    }

    /// @dev Sliding-window budget: previous bucket is weighted by how much of
    /// it still overlaps the last 24h. Caller guarantees amount <= highValue
    /// (<= uint128 max), so the uint128 casts cannot truncate.
    function _consumeVelocity(address account, address token, uint256 amount) internal returns (bool) {
        (, uint256 limit) = policyOf(account, token);
        Velocity storage v = velocity[account][token];
        uint256 w = VELOCITY_WINDOW;

        if (v.windowStart == 0) {
            v.windowStart = uint64(block.timestamp);
        } else {
            uint256 elapsed0 = block.timestamp - v.windowStart;
            if (elapsed0 >= 2 * w) {
                v.prevSpent = 0;
                v.curSpent = 0;
                v.prevCount = 0;
                v.curCount = 0;
                v.windowStart = uint64(block.timestamp);
            } else if (elapsed0 >= w) {
                v.prevSpent = v.curSpent;
                v.prevCount = v.curCount;
                v.curSpent = 0;
                v.curCount = 0;
                v.windowStart += uint64(w);
            }
        }

        uint256 prevWeight = w - (block.timestamp - v.windowStart);
        uint256 spent = (uint256(v.prevSpent) * prevWeight) / w + v.curSpent + amount;
        uint256 count = (uint256(v.prevCount) * prevWeight) / w + v.curCount + 1;
        if (spent > limit || count > MAX_TXS_PER_WINDOW) return false;

        v.curSpent += uint128(amount);
        v.curCount += 1;
        return true;
    }

    /// @notice Remaining budget right now (for UIs / the notifier).
    function remainingBudget(address account, address token) external view returns (uint256 amountLeft, uint256 txsLeft) {
        (, uint256 limit) = policyOf(account, token);
        Velocity memory v = velocity[account][token];
        uint256 w = VELOCITY_WINDOW;
        uint256 cur = v.curSpent;
        uint256 prev = v.prevSpent;
        uint256 curC = v.curCount;
        uint256 prevC = v.prevCount;
        uint256 start = v.windowStart;
        if (start != 0) {
            uint256 el = block.timestamp - start;
            if (el >= 2 * w) {
                cur = 0; prev = 0; curC = 0; prevC = 0; start = block.timestamp;
            } else if (el >= w) {
                prev = cur; prevC = curC; cur = 0; curC = 0; start += w;
            }
        } else {
            start = block.timestamp;
        }
        uint256 pw = w - (block.timestamp - start);
        uint256 spent = (prev * pw) / w + cur;
        uint256 cnt = (prevC * pw) / w + curC;
        amountLeft = spent >= limit ? 0 : limit - spent;
        txsLeft = cnt >= MAX_TXS_PER_WINDOW ? 0 : MAX_TXS_PER_WINDOW - cnt;
    }

    // [CRIT FIXED] This previously always returned (0, 0, 0) regardless of the
    // actual call, so _isHighValue() always saw amount=0 and NEVER classified
    // any standard-signature transaction as high-value — the $10k delay
    // threshold was completely inert; an attacker with just the standard
    // signing key could move funds of any size instantly. Now performs a
    // best-effort decode of the account's execute() call, and — critically —
    // fails CLOSED: any call shape this can't confidently prove is a
    // low-value transfer is reported as `amount = type(uint256).max`, which
    // routes it through the delay/guardian path rather than silently letting
    // it through. Only plain native-ETH sends and recognized ERC-20
    // transfer() calls, via the single-call ERC-7579 execute() mode, are
    // decoded to their real amount.
    function _decodeCall(bytes calldata callData)
        internal
        view
        returns (address token, uint256 amount, address recipient)
    {
        token = address(0);
        amount = type(uint256).max; // fail closed by default
        recipient = address(0);

        if (callData.length < 4) return (token, amount, recipient);
        if (bytes4(callData[:4]) != IERC7579Account.execute.selector) {
            return (token, amount, recipient); // not the standard execute() entrypoint — fail closed
        }
        if (callData.length < 4 + 64) return (token, amount, recipient);

        (bytes32 mode, bytes memory executionCalldata) = abi.decode(callData[4:], (bytes32, bytes));

        // Only decode the single-call mode (top byte 0x00). Batch calls
        // (0x01) and anything else fail closed rather than being misread.
        if (bytes1(mode) != 0x00) return (token, amount, recipient);

        // ERC-7579 single-execution packing: 20-byte target || 32-byte value || calldata
        if (executionCalldata.length < 52) return (token, amount, recipient);

        address target = _toAddress(executionCalldata, 0);
        uint256 value = _toUint256(executionCalldata, 20);

        if (executionCalldata.length == 52) {
            // Plain native-ETH send, no inner calldata.
            return (address(0), value, target);
        }

        bytes memory innerData = slice(executionCalldata, 52, executionCalldata.length - 52);

        // Self-calls: only the protective queue/cancel entrypoints are allowed
        // through the standard path (they move no funds). Everything else aimed
        // at this module (setTokenPolicy, ...) stays fail-closed.
        if (target == address(this) && value == 0 && innerData.length >= 4) {
            bytes4 selfSel = _toBytes4(innerData, 0);
            if (selfSel == TimeLockValidator.initiateDelayedTx.selector || selfSel == TimeLockValidator.cancelTx.selector) {
                return (address(0), 0, address(0));
            }
        }

        // value must be 0 for the ERC-20 shape; ETH attached to a transfer-looking call
        // would otherwise be ignored by the budget (fail closed instead).
        if (value == 0 && innerData.length >= 4 + 64) {
            bytes4 innerSelector = _toBytes4(innerData, 0);
            if (innerSelector == IERC20Transfer.transfer.selector) {
                address to = _toAddress(innerData, 16); // 4-byte selector + 12-byte address padding
                uint256 amt = _toUint256(innerData, 36); // 4 + 32
                return (target, amt, to);
            }
        }

        // Any other call shape (approve, transferFrom, arbitrary contract
        // call, etc.) — fail closed rather than assuming it's harmless.
        return (token, amount, recipient);
    }

    function _toAddress(bytes memory data, uint256 offset) internal pure returns (address addr) {
        uint160 result;
        for (uint256 i = 0; i < 20; i++) {
            result = (result << 8) | uint160(uint8(data[offset + i]));
        }
        return address(result);
    }

    function _toUint256(bytes memory data, uint256 offset) internal pure returns (uint256 result) {
        for (uint256 i = 0; i < 32; i++) {
            result = (result << 8) | uint256(uint8(data[offset + i]));
        }
    }

    function _toBytes4(bytes memory data, uint256 offset) internal pure returns (bytes4 result) {
        for (uint256 i = 0; i < 4; i++) {
            result |= bytes4(data[offset + i]) >> (i * 8);
        }
    }

    function slice(bytes memory data, uint256 start, uint256 length) internal pure returns (bytes memory) {
        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = data[start + i];
        }
        return result;
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        // 1 = validator, 2 = executor (needed for executeFromExecutor in _execute)
        return moduleTypeId == MODULE_TYPE_VALIDATOR || moduleTypeId == 2;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return accounts[smartAccount].initialized;
    }
    // [CRIT-1 FIXED] Duplicate validateUserOp removed — it returned 0 (SIG_VALIDATION_SUCCESS)
    // unconditionally, bypassing every check the primary validateUserOp implementation enforces.

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }
}
