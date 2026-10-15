// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IValidator} from "erc7579/interfaces/IERC7579Module.sol";
import {IERC7579Account} from "erc7579/interfaces/IERC7579Account.sol";
import {ModeLib} from "erc7579/lib/ModeLib.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";
import {CallDecoder} from "./lib/CallDecoder.sol";
import {RouterGated} from "./lib/RouterGated.sol";

/// @dev Implemented by BiometricValidator: verifies a WebAuthn assertion made with one of
/// `account`'s enrolled passkeys (the fingerprint registered at signup) over `challenge`.
interface IBiometricVerifier {
    function verifyConfirmation(address account, bytes32 challenge, bytes calldata signature)
        external
        view
        returns (bool);
}

interface IEntryPointDeposits {
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @title TimeLockValidator
 * @notice The "limited authority" half of the EthosiFi Vault's two-tier authorization.
 *
 *  TIER 1  passkey / fingerprint  -> BiometricValidator -> full authority.
 *  TIER 2  spending key (this)    -> small, rate-limited transfers only. Everything else is
 *                                    impossible for this key, and large / over-budget amounts
 *                                    must be queued and released with the fingerprint.
 *
 * One contract plays three roles for an account:
 *  - IValidator : validates userOps signed by the account's SPENDING KEY (its own signer; it never
 *                 trusts the account's other validators). Only plain native sends / ERC-20
 *                 transfer(), at most `highValue` each, plus queue/cancel of delayed txs.
 *  - IExecutor  : releases a queued tx via account.executeFromExecutor once the fingerprint
 *                 confirms it. Unconfirmed queued txs die after `delay` (default 48h).
 *  - ISubHook   : plugged into the account's EthosiHookRouter. When the current transaction
 *                 contains a spending-key op, every transfer executed in it is charged against a
 *                 per-token EXACT sliding-window budget (24h, <= 10 txs, <= windowLimit).
 *
 * Why the budget lives in the hook, not in validation: ERC-4337 validation may not read
 * TIMESTAMP (ERC-7562) and a sliding window needs it. Validation instead raises a transient flag
 * that only lives for the current transaction; EntryPoint v0.7 validates every op in a bundle
 * before executing any, so every execution in that tx is budgeted (conservative, never lax).
 *
 * Fingerprint release: SMS/push is only a notification. The release authorization is a WebAuthn
 * assertion over a challenge bound to (chain, this contract, account, txHash); a SIM-swapper who
 * receives the SMS can do nothing with it, and the fail-safe if nothing is confirmed is expiry.
 */
contract TimeLockValidator is IValidator, RouterGated {
    using SignatureCheckerLib for address;

    uint256 constant SIG_VALIDATION_SUCCESS = 0;
    uint256 constant SIG_VALIDATION_FAILED = 1;

    uint256 public constant DEFAULT_DELAY = 48 hours;
    uint256 public constant MIN_DELAY = 1 hours;
    uint256 public constant MAX_DELAY = 30 days;
    uint256 public constant MAX_OPEN_PENDING = 5;

    // Anti drip-drain: exact sliding window over the last MAX_TXS_PER_WINDOW spends.
    uint256 public constant VELOCITY_WINDOW = 24 hours;
    uint256 public constant MAX_TXS_PER_WINDOW = 10;

    // Gas griefing guard. A spending-key op can cost gas (paid to whoever bundles it, i.e. possibly the
    // thief). Two bounds: per-op gas limits are capped, AND the op must be fully prefunded from the
    // account's EntryPoint deposit (its "gas tank"), so the account's own balance can never be
    // touched for gas by this key. Worst case = the tank, which the owner sizes.
    uint256 public constant MAX_VERIFICATION_GAS = 500_000;
    uint256 public constant MAX_CALL_GAS = 500_000;
    uint256 public constant MAX_PRE_VERIFICATION_GAS = 200_000;

    /// @dev BiometricValidator used to verify fingerprint confirmations.
    address public immutable biometricVerifier;
    /// @dev ERC-4337 EntryPoint whose deposit is the vault's gas tank.
    address public immutable entryPoint;

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

    struct Spend {
        uint64 ts;
        uint192 amount;
    }

    struct AccountConfig {
        bool initialized;
        address signer; // spending key (EOA or ERC-1271 contract); address(0) = limited path disabled
        uint256 delay;
        uint256 txNonce;
        uint256 openPending;
        address[] guardians;
    }

    struct PendingTx {
        address token;
        uint256 amount;
        address recipient;
        uint256 createdAt; // non-zero marker
        uint256 expiresAt; // fingerprint must confirm before this or the tx is dead
        bool executed;
        bool cancelled;
    }

    mapping(address => AccountConfig) private _cfg;
    mapping(address => mapping(bytes32 => PendingTx)) private _pending;
    mapping(address => mapping(address => TokenPolicy)) public tokenPolicy; // account => token
    mapping(address => mapping(address => PendingPolicy)) public pendingPolicy;
    mapping(address => mapping(address => Spend[10])) private _ring; // account => token => spends

    event SignerChanged(address indexed account, address indexed signer);
    event PolicyChanged(address indexed account, address indexed token, uint256 highValue, uint256 windowLimit);
    event PolicyIncreaseQueued(
        address indexed account, address indexed token, uint256 highValue, uint256 windowLimit, uint256 applyAfter
    );
    event PolicyIncreaseCancelled(address indexed account, address indexed token, address by);
    event TxDelayed(bytes32 indexed txHash, address indexed account, uint256 expiresAt);
    /// @dev Trigger for the off-chain notifier: text the owner a link to confirm this exact
    /// transaction with their fingerprint.
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
    event TxCancelled(bytes32 indexed txHash, address indexed by);

    error BudgetExceeded(address token, uint256 amount);
    error TooManyOpen();
    error NotAuthorized();

    constructor(address biometricVerifier_, address router_, address entryPoint_) RouterGated(router_) {
        require(biometricVerifier_ != address(0) && entryPoint_ != address(0), "Zero address");
        biometricVerifier = biometricVerifier_;
        entryPoint = entryPoint_;
    }

    // ─── Module lifecycle (msg.sender = account) ──────────────────────────────

    struct InitPolicy {
        address token;
        uint128 highValue;
        uint128 windowLimit;
    }

    /// @param data abi.encode(address signer, address[] guardians, uint256 delay, InitPolicy[] policies)
    function onInstall(bytes calldata data) external override {
        // Idempotent: the account installs this module as validator AND executor.
        if (_cfg[msg.sender].initialized) return;

        (address signer, address[] memory guardians, uint256 delay, InitPolicy[] memory policies) =
            abi.decode(data, (address, address[], uint256, InitPolicy[]));
        require(guardians.length <= 10, "Too many guardians");
        if (delay == 0) delay = DEFAULT_DELAY;
        require(delay >= MIN_DELAY && delay <= MAX_DELAY, "Bad delay");

        AccountConfig storage c = _cfg[msg.sender];
        c.initialized = true;
        c.signer = signer;
        c.delay = delay;
        for (uint256 i; i < guardians.length; i++) {
            require(guardians[i] != address(0), "Zero guardian");
            c.guardians.push(guardians[i]);
        }
        for (uint256 i; i < policies.length; i++) {
            tokenPolicy[msg.sender][policies[i].token] =
                TokenPolicy(true, policies[i].highValue, policies[i].windowLimit);
            emit PolicyChanged(msg.sender, policies[i].token, policies[i].highValue, policies[i].windowLimit);
        }
        emit SignerChanged(msg.sender, signer);
    }

    function onUninstall(bytes calldata) external override {
        // The account is uninstalling one of its roles. Keep pending state (so a queued tx can
        // still be cancelled) but disable the spending key.
        _cfg[msg.sender].signer = address(0);
        emit SignerChanged(msg.sender, address(0));
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == 1 || moduleTypeId == 2; // validator, executor
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _cfg[smartAccount].initialized;
    }

    /// @notice Replace (or, with address(0), disable) the spending key. Account-only, so it needs
    /// the passkey: the spending key can never rotate itself.
    function setSigner(address newSigner) external {
        require(_cfg[msg.sender].initialized, "Not installed");
        _cfg[msg.sender].signer = newSigner;
        emit SignerChanged(msg.sender, newSigner);
    }

    // ─── IValidator: spending-key userOps ─────────────────────────────────────

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        override
        returns (uint256)
    {
        AccountConfig storage c = _cfg[msg.sender];
        address signer = c.signer;
        if (!c.initialized || signer == address(0)) return SIG_VALIDATION_FAILED;

        // gas caps (anti gas-griefing)
        if (
            uint128(bytes16(userOp.accountGasLimits)) > MAX_VERIFICATION_GAS
                || uint128(uint256(userOp.accountGasLimits)) > MAX_CALL_GAS
                || userOp.preVerificationGas > MAX_PRE_VERIFICATION_GAS
        ) return SIG_VALIDATION_FAILED;

        // The op must be paid entirely from the account's EntryPoint deposit (gas tank), never from
        // the account balance (EntryPoint v0.7: required = (all gas limits) * maxFeePerGas).
        if (userOp.paymasterAndData.length == 0) {
            uint256 required =
                (uint256(uint128(bytes16(userOp.accountGasLimits)))
                        + uint256(uint128(uint256(userOp.accountGasLimits)))
                        + userOp.preVerificationGas) * uint256(uint128(uint256(userOp.gasFees)));
            if (IEntryPointDeposits(entryPoint).balanceOf(msg.sender) < required) return SIG_VALIDATION_FAILED;
        }

        // The signature comes first: nothing below is evaluated for unsigned garbage.
        if (!_validSig(signer, userOpHash, userOp.signature)) return SIG_VALIDATION_FAILED;

        (bool ok, address target, uint256 value, bytes calldata data) = CallDecoder.decodeExecuteSingle(userOp.callData);
        if (!ok) return SIG_VALIDATION_FAILED;

        if (target == address(this)) {
            // Only the protective queue / cancel entrypoints, exact calldata sizes, no ETH.
            if (value != 0 || data.length < 4) return SIG_VALIDATION_FAILED;
            bytes4 sel = bytes4(data[:4]);
            if (sel == this.initiateDelayedTx.selector && data.length == 4 + 96) {
                // fall through: moves no funds
            } else if (sel == this.cancelTx.selector && data.length == 4 + 64) {
                // fall through
            } else {
                return SIG_VALIDATION_FAILED;
            }
        } else {
            CallDecoder.Transfer memory t = CallDecoder.classify(target, value, data);
            if (t.kind == 0 || t.recipient == address(0) || t.amount == 0) return SIG_VALIDATION_FAILED;
            (uint256 highValue,) = policyOf(msg.sender, t.token);
            if (t.amount > highValue) return SIG_VALIDATION_FAILED;
        }

        // Budget enforcement happens in preCheck during execution; flag this transaction.
        _setLimitedFlag(msg.sender);
        return SIG_VALIDATION_SUCCESS;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure override returns (bytes4) {
        return 0xffffffff; // the spending key may never sign off-chain messages (permits etc.)
    }

    function _validSig(address signer, bytes32 hash, bytes calldata sig) internal view returns (bool) {
        if (signer.isValidSignatureNow(hash, sig)) return true;
        return signer.isValidSignatureNow(ECDSA.toEthSignedMessageHash(hash), sig);
    }

    // transient "a spending-key op was validated in this tx for <account>" flag
    function _flagSlot(address account) private pure returns (bytes32) {
        return keccak256(abi.encode("ethosifi.timelock.limited", account));
    }

    function _setLimitedFlag(address account) private {
        bytes32 s = _flagSlot(account);
        assembly {
            tstore(s, 1)
        }
    }

    function _limitedFlag(address account) private view returns (bool f) {
        bytes32 s = _flagSlot(account);
        assembly {
            f := tload(s)
        }
    }

    // ─── Sub-hook: velocity budget ────────────────────────────────────────────

    function preCheck(address account, address target, uint256 value, bytes calldata callData)
        external
        onlyRouter
        returns (bytes memory)
    {
        if (!_limitedFlag(account)) return "";
        CallDecoder.Transfer memory t = CallDecoder.classify(target, value, callData);
        if (t.kind == 0) return ""; // queue/cancel self-calls etc. move no funds
        (uint256 highValue, uint256 limit) = policyOf(account, t.token);
        if (t.amount > highValue) revert BudgetExceeded(t.token, t.amount);
        _consumeVelocity(account, t.token, t.amount, limit);
        return "";
    }

    function postCheck(bytes calldata) external pure {}

    function _consumeVelocity(address account, address token, uint256 amount, uint256 limit) internal {
        Spend[10] storage ring = _ring[account][token];
        uint256 spent = amount;
        uint256 count = 1;
        uint256 free = type(uint256).max;
        for (uint256 i; i < 10; i++) {
            Spend memory e = ring[i];
            if (e.ts != 0 && uint256(e.ts) + VELOCITY_WINDOW > block.timestamp) {
                spent += e.amount;
                count++;
            } else if (free == type(uint256).max) {
                free = i;
            }
        }
        if (spent > limit || count > MAX_TXS_PER_WINDOW || free == type(uint256).max) {
            revert BudgetExceeded(token, amount);
        }
        // amount <= highValue <= uint128.max here, so the cast cannot truncate
        ring[free] = Spend(uint64(block.timestamp), uint192(amount));
    }

    /// @notice Remaining budget right now (for UIs / the notifier).
    function remainingBudget(address account, address token)
        external
        view
        returns (uint256 amountLeft, uint256 txsLeft)
    {
        (, uint256 limit) = policyOf(account, token);
        uint256 spent;
        uint256 count;
        Spend[10] storage ring = _ring[account][token];
        for (uint256 i; i < 10; i++) {
            Spend memory e = ring[i];
            if (e.ts != 0 && uint256(e.ts) + VELOCITY_WINDOW > block.timestamp) {
                spent += e.amount;
                count++;
            }
        }
        amountLeft = spent >= limit ? 0 : limit - spent;
        txsLeft = count >= MAX_TXS_PER_WINDOW ? 0 : MAX_TXS_PER_WINDOW - count;
    }

    // ─── Delayed transactions + fingerprint release ───────────────────────────

    /// @notice Queue a transfer. Called by the account (via passkey OR spending key). Moves no
    /// funds; nothing happens until the fingerprint confirms it, and it dies after `delay`.
    function initiateDelayedTx(address token, uint256 amount, address recipient) external returns (bytes32 txHash) {
        AccountConfig storage c = _cfg[msg.sender];
        require(c.initialized, "Not installed");
        require(amount > 0 && recipient != address(0), "Bad tx");
        if (c.openPending >= MAX_OPEN_PENDING) revert TooManyOpen();
        c.openPending++;

        txHash = keccak256(abi.encode(block.chainid, address(this), msg.sender, token, amount, recipient, c.txNonce++));
        PendingTx storage p = _pending[msg.sender][txHash];
        p.token = token;
        p.amount = amount;
        p.recipient = recipient;
        p.createdAt = block.timestamp;
        p.expiresAt = block.timestamp + c.delay;

        emit TxDelayed(txHash, msg.sender, p.expiresAt);
        emit BiometricConfirmationRequested(msg.sender, txHash, token, amount, recipient, p.expiresAt);
    }

    /// @notice Challenge the owner's authenticator must sign to release `txHash`.
    function confirmationChallenge(address account, bytes32 txHash) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), account, txHash));
    }

    /// @notice Release a queued tx using a fingerprint (WebAuthn) assertion from one of the
    /// account's enrolled passkeys. Callable by anyone (the user's app relays it): the
    /// assertion is the authorization, not msg.sender. Fails after `expiresAt`.
    function confirmAndRelease(address account, bytes32 txHash, bytes calldata biometricSig) external {
        PendingTx storage p = _pending[account][txHash];
        require(p.createdAt > 0, "Not found");
        require(!p.cancelled, "Cancelled");
        require(!p.executed, "Already executed");
        require(block.timestamp <= p.expiresAt, "Expired");
        require(
            IBiometricVerifier(biometricVerifier)
                .verifyConfirmation(account, confirmationChallenge(account, txHash), biometricSig),
            "Invalid fingerprint"
        );

        // effects before interaction
        p.executed = true;
        _cfg[account].openPending--;
        emit TxExecuted(txHash);

        address target;
        uint256 value;
        bytes memory inner;
        if (p.token == address(0)) {
            target = p.recipient;
            value = p.amount;
        } else {
            target = p.token;
            inner = abi.encodeWithSelector(0xa9059cbb, p.recipient, p.amount); // transfer(address,uint256)
        }
        // ERC-7579 single exec is PACKED: target(20) || value(32) || calldata
        IERC7579Account(account)
            .executeFromExecutor(ModeLib.encodeSimpleSingle(), abi.encodePacked(target, value, inner));
    }

    /// @notice Mark an unconfirmed tx as dead after the window (anyone).
    function expireTx(address account, bytes32 txHash) external {
        PendingTx storage p = _pending[account][txHash];
        require(p.createdAt > 0, "Not found");
        require(!p.executed && !p.cancelled, "Finalised");
        require(block.timestamp > p.expiresAt, "Not expired");
        p.cancelled = true;
        _cfg[account].openPending--;
        emit TxExpired(txHash, account);
    }

    /// @notice Cancel a pending tx. The account itself or any guardian may cancel.
    function cancelTx(address account, bytes32 txHash) external {
        if (msg.sender != account && !_isGuardian(account, msg.sender)) revert NotAuthorized();
        PendingTx storage p = _pending[account][txHash];
        require(p.createdAt > 0, "Not found");
        require(!p.executed, "Already executed");
        require(!p.cancelled, "Already cancelled");
        p.cancelled = true;
        _cfg[account].openPending--;
        emit TxCancelled(txHash, msg.sender);
    }

    function getPending(address account, bytes32 txHash) external view returns (PendingTx memory) {
        return _pending[account][txHash];
    }

    function getConfig(address account)
        external
        view
        returns (address signer, uint256 delay, uint256 openPending, address[] memory guardians)
    {
        AccountConfig storage c = _cfg[account];
        return (c.signer, c.delay, c.openPending, c.guardians);
    }

    function _isGuardian(address account, address who) internal view returns (bool) {
        address[] storage g = _cfg[account].guardians;
        for (uint256 i = 0; i < g.length; i++) {
            if (g[i] == who) return true;
        }
        return false;
    }

    // ─── Per-token policy ─────────────────────────────────────────────────────

    function policyOf(address account, address token) public view returns (uint256 highValue, uint256 windowLimit) {
        TokenPolicy memory p = tokenPolicy[account][token];
        // Fail closed: a token with no policy cannot be moved by the spending key at all. Enabling
        // it later is a "loosening" and therefore queued for `delay`.
        return (p.highValue, p.windowLimit);
    }

    /// @notice Set per-token limits (raw token units; native via token = address(0)).
    /// Tightening applies immediately. Any loosening is queued for `delay` and can be cancelled by
    /// the account or a guardian, so a stolen key cannot just raise the cap. Account-only (the
    /// spending key cannot call it).
    function setTokenPolicy(address token, uint128 highValue, uint128 windowLimit) external {
        AccountConfig storage c = _cfg[msg.sender];
        require(c.initialized, "Not installed");
        (uint256 curHV, uint256 curWL) = policyOf(msg.sender, token);

        if (highValue <= curHV && windowLimit <= curWL) {
            tokenPolicy[msg.sender][token] = TokenPolicy(true, highValue, windowLimit);
            delete pendingPolicy[msg.sender][token];
            emit PolicyChanged(msg.sender, token, highValue, windowLimit);
        } else {
            uint256 applyAfter = block.timestamp + c.delay;
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
        if (msg.sender != account && !_isGuardian(account, msg.sender)) revert NotAuthorized();
        require(pendingPolicy[account][token].applyAfter != 0, "Nothing queued");
        delete pendingPolicy[account][token];
        emit PolicyIncreaseCancelled(account, token, msg.sender);
    }
}
