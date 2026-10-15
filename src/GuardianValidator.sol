// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {IModule} from "erc7579/interfaces/IERC7579Module.sol";
import {ReentrancyGuard} from "solady/utils/ReentrancyGuard.sol";
import {IERC7579Account} from "erc7579/interfaces/IERC7579Account.sol";
import {ModeLib} from "erc7579/lib/ModeLib.sol";

/**
 * @title GuardianValidator
 * @author EthosiFi (founder@ethosifi.com)
 * @notice ERC-7579 validator module — weighted social recovery with time delays
 * for the EthosiFi Vault.
 *
 * Recovery model
 * ──────────────
 * • Guardians are assigned weights (e.g. family=3, friend=1, hardware key=5).
 * • A recovery is initiated by ANY guardian or the account owner.
 * • Other guardians approve during the RECOVERY_DELAY window.
 * • Once total weight ≥ threshold AND delay has elapsed → execution is unlocked.
 * • Any single guardian can cancel during the delay (veto power).
 *         • Execution rotates the account's validator module (BiometricValidator credential).
 * • Each guardian has a per-approval cooldown to prevent rapid re-voting.
 * • Only one active recovery per account at a time.
 *
 * This validator does NOT validate standard UserOps (always returns FAILED).
 * It is a recovery-only module — it is not in the hot path.
 *
 * @dev BSL 1.1 — non-commercial use free; commercial license: founder@ethosifi.com
 * Converts to GPL-3.0 on 2029-01-01.
 */
contract GuardianValidator is IModule, ReentrancyGuard {
    // ─────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────

    uint256 public constant MODULE_TYPE_EXECUTOR = 2;

    /// @notice BiometricValidator whose credentials this module is allowed to replace on recovery.
    address public immutable biometricValidator;

    constructor(address biometricValidator_) {
        require(biometricValidator_ != address(0), "Zero validator");
        biometricValidator = biometricValidator_;
    }

    /// @notice Mandatory delay between recovery initiation and execution.
    uint256 public constant RECOVERY_DELAY = 48 hours;

    /// @notice Minimum time a guardian must wait between approvals on the same account.
    uint256 public constant APPROVAL_COOLDOWN = 6 hours;

    /// @notice Maximum number of guardians per account (gas safety bound).
    uint256 public constant MAX_GUARDIANS = 10;

    // ─────────────────────────────────────────────────────────────
    // Types
    // ─────────────────────────────────────────────────────────────

    struct Guardian {
        address addr;
        uint256 weight;
        bytes32 identityHash; // off-chain identity commitment (e.g. keccak256(email))
    }

    struct AccountConfig {
        bool initialized;
        uint256 threshold; // minimum total weight to approve recovery
        uint256 guardianCount;
    }

    struct RecoveryRequest {
        bytes32 newCredentialId; // new passkey credential id
        uint256[2] newPubKey; // new passkey P-256 public key (x, y)
        uint256 initiatedAt;
        uint256 totalWeight;
        bool executed;
        bool cancelled;
        address initiator;
    }

    // ─────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────

    /// @dev account → config
    mapping(address => AccountConfig) private _configs;

    /// @dev account → guardian address → Guardian
    mapping(address => mapping(address => Guardian)) private _guardians;

    /// @dev account → ordered list of guardian addresses (for iteration)
    mapping(address => address[]) private _guardianList;

    /// @dev account → active RecoveryRequest
    mapping(address => RecoveryRequest) private _recoveries;

    /// @dev account => recoveryInitiatedAt => guardian => approved
    ///      Using initiatedAt as a nonce prevents old approvals carrying into new requests.
    mapping(address => mapping(uint256 => mapping(address => bool))) private _approvals;

    /// @dev account => guardian => last approval timestamp (for cooldown)
    mapping(address => mapping(address => uint256)) private _lastApproval;

    // ─────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────

    event RecoveryInitiated(
        address indexed account, address indexed initiator, bytes32 indexed newCredentialId, uint256 executeAfter
    );
    event GuardianApproved(address indexed account, address indexed guardian, uint256 weight, uint256 totalWeight);
    event RecoveryExecuted(address indexed account, bytes32 indexed newCredentialId);
    event RecoveryCancelled(address indexed account, address indexed cancelledBy);
    event GuardianAdded(address indexed account, address indexed guardian, uint256 weight);
    event GuardianRemoved(address indexed account, address indexed guardian);
    event ThresholdChanged(address indexed account, uint256 newThreshold);

    // ─────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────

    // [FIXED] Renamed — these clashed with IModule's own
    // AlreadyInitialized(address)/NotInitialized(address) errors (inherited
    // via IValidator, different arity, same name — compile error).
    error ModuleAlreadyInitialized();
    error ModuleNotInitialized();
    error NotGuardian();
    error NotGuardianOrOwner();
    error RecoveryPending();
    error NoRecoveryActive();
    error AlreadyExecuted();
    error AlreadyCancelled();
    error AlreadyApproved();
    error CooldownActive();
    error DelayNotElapsed();
    error InsufficientWeight();
    error TooManyGuardians();
    error InvalidGuardian();
    error InvalidThreshold();
    error InvalidWeight();
    error GuardianAlreadyExists();
    error GuardianNotFound();
    error ZeroAddress();
    error CannotCancelExecuted();

    // ─────────────────────────────────────────────────────────────
    // ERC-7579 Module lifecycle
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice Install the module on a smart account.
     * @param data ABI-encoded (Guardian[] guardians, uint256 threshold)
     * Guardian: (address addr, uint256 weight, bytes32 identityHash)
     * threshold: minimum total weight required for recovery approval.
     */
    function onInstall(bytes calldata data) external override {
        if (_configs[msg.sender].initialized) revert ModuleAlreadyInitialized();

        (Guardian[] memory initialGuardians, uint256 _threshold) = abi.decode(data, (Guardian[], uint256));

        if (initialGuardians.length == 0) revert InvalidGuardian();
        if (initialGuardians.length > MAX_GUARDIANS) revert TooManyGuardians();
        if (_threshold == 0) revert InvalidThreshold();

        uint256 totalWeight = 0;

        for (uint256 i = 0; i < initialGuardians.length; i++) {
            Guardian memory g = initialGuardians[i];
            if (g.addr == address(0)) revert ZeroAddress();
            if (g.weight == 0) revert InvalidWeight();
            if (_guardians[msg.sender][g.addr].addr != address(0)) revert GuardianAlreadyExists();

            // Deduplicate
            for (uint256 j = i + 1; j < initialGuardians.length; j++) {
                require(initialGuardians[j].addr != g.addr, "Duplicate guardian");
            }

            _guardians[msg.sender][g.addr] = g;
            _guardianList[msg.sender].push(g.addr);
            totalWeight += g.weight;

            emit GuardianAdded(msg.sender, g.addr, g.weight);
        }

        // Threshold must be reachable
        require(totalWeight >= _threshold, "Threshold unreachable");

        _configs[msg.sender] =
            AccountConfig({initialized: true, threshold: _threshold, guardianCount: initialGuardians.length});
    }

    /**
     * @notice Uninstall — clears all guardian state.
     * If a recovery is pending it is implicitly abandoned.
     */
    function onUninstall(bytes calldata) external override {
        address[] storage list = _guardianList[msg.sender];
        for (uint256 i = 0; i < list.length; i++) {
            delete _guardians[msg.sender][list[i]];
        }
        delete _guardianList[msg.sender];
        delete _recoveries[msg.sender];
        delete _configs[msg.sender];
    }

    // ─────────────────────────────────────────────────────────────
    // Recovery flow
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice Initiate a recovery request. Callable by any guardian OR the account itself.
     * Executing it (after the delay and with enough guardian weight) REPLACES all of the
     * account's passkeys with the new one; the new passkey is the only way back in.
     * @param newCredentialId credential id of the replacement passkey
     * @param newPubKey P-256 (x, y) public key of the replacement passkey
     */
    function initiateRecovery(address account, bytes32 newCredentialId, uint256[2] calldata newPubKey) external {
        if (newCredentialId == bytes32(0) || newPubKey[0] == 0 || newPubKey[1] == 0) revert InvalidGuardian();
        AccountConfig storage cfg = _configs[account];
        if (!cfg.initialized) revert ModuleNotInitialized();

        // Only a guardian or the account itself may initiate
        bool callerIsGuardian = _guardians[account][msg.sender].addr != address(0);
        bool callerIsAccount = msg.sender == account;
        if (!callerIsGuardian && !callerIsAccount) revert NotGuardianOrOwner();

        RecoveryRequest storage req = _recoveries[account];
        if (req.initiatedAt > 0 && !req.executed && !req.cancelled) revert RecoveryPending();

        // Reset any previous (executed or cancelled) request
        delete _recoveries[account];

        RecoveryRequest storage newReq = _recoveries[account];
        newReq.newCredentialId = newCredentialId;
        newReq.newPubKey = newPubKey;
        newReq.initiatedAt = block.timestamp;
        newReq.initiator = msg.sender;

        // If initiator is a guardian, count their weight immediately
        if (callerIsGuardian) {
            Guardian storage g = _guardians[account][msg.sender];
            _approvals[account][block.timestamp][msg.sender] = true;
            _lastApproval[account][msg.sender] = block.timestamp;
            newReq.totalWeight += g.weight;
            emit GuardianApproved(account, msg.sender, g.weight, newReq.totalWeight);
        }

        emit RecoveryInitiated(account, msg.sender, newCredentialId, block.timestamp + RECOVERY_DELAY);
    }

    /**
     * @notice Guardian approves the active recovery request.
     * @param account The account being recovered.
     */
    function approveRecovery(address account) external nonReentrant {
        AccountConfig storage cfg = _configs[account];
        if (!cfg.initialized) revert ModuleNotInitialized();

        Guardian storage g = _guardians[account][msg.sender];
        if (g.addr == address(0)) revert NotGuardian();

        RecoveryRequest storage req = _recoveries[account];
        if (req.initiatedAt == 0) revert NoRecoveryActive();
        if (req.executed) revert AlreadyExecuted();
        if (req.cancelled) revert AlreadyCancelled();

        // Approval nonce tied to initiatedAt — prevents approvals from old requests counting
        if (_approvals[account][req.initiatedAt][msg.sender]) revert AlreadyApproved();

        // Cooldown check
        uint256 lastApproval = _lastApproval[account][msg.sender];
        if (lastApproval > 0 && block.timestamp < lastApproval + APPROVAL_COOLDOWN) {
            revert CooldownActive();
        }

        // Record approval
        _approvals[account][req.initiatedAt][msg.sender] = true;
        _lastApproval[account][msg.sender] = block.timestamp;
        req.totalWeight += g.weight;

        emit GuardianApproved(account, msg.sender, g.weight, req.totalWeight);

        // Auto-execute if threshold met AND delay elapsed
        if (req.totalWeight >= cfg.threshold && block.timestamp >= req.initiatedAt + RECOVERY_DELAY) {
            _executeRecovery(account);
        }
    }

    /**
     * @notice Execute recovery after delay has elapsed and threshold is met.
     * Anyone may call this once conditions are satisfied (trustless execution).
     * @param account The account being recovered.
     */
    function executeRecovery(address account) external nonReentrant {
        AccountConfig storage cfg = _configs[account];
        if (!cfg.initialized) revert ModuleNotInitialized();

        RecoveryRequest storage req = _recoveries[account];
        if (req.initiatedAt == 0) revert NoRecoveryActive();
        if (req.executed) revert AlreadyExecuted();
        if (req.cancelled) revert AlreadyCancelled();
        if (req.totalWeight < cfg.threshold) revert InsufficientWeight();
        if (block.timestamp < req.initiatedAt + RECOVERY_DELAY) revert DelayNotElapsed();

        _executeRecovery(account);
    }

    /**
     * @notice Cancel an active recovery request.
     * Any guardian OR the account itself can cancel during the delay window.
     * @param account The account whose recovery is being cancelled.
     */
    function cancelRecovery(address account) external {
        AccountConfig storage cfg = _configs[account];
        if (!cfg.initialized) revert ModuleNotInitialized();

        bool callerIsGuardian = _guardians[account][msg.sender].addr != address(0);
        bool callerIsAccount = msg.sender == account;
        if (!callerIsGuardian && !callerIsAccount) revert NotGuardianOrOwner();

        RecoveryRequest storage req = _recoveries[account];
        if (req.initiatedAt == 0) revert NoRecoveryActive();
        if (req.executed) revert CannotCancelExecuted();
        if (req.cancelled) revert AlreadyCancelled();

        req.cancelled = true;
        emit RecoveryCancelled(account, msg.sender);
    }

    // ─────────────────────────────────────────────────────────────
    // Guardian management (account-only)
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice Add a new guardian. Only callable by the account itself.
     */
    function addGuardian(address guardianAddr, uint256 weight, bytes32 identityHash) external {
        AccountConfig storage cfg = _configs[msg.sender];
        if (!cfg.initialized) revert ModuleNotInitialized();
        if (guardianAddr == address(0)) revert ZeroAddress();
        if (weight == 0) revert InvalidWeight();
        if (cfg.guardianCount >= MAX_GUARDIANS) revert TooManyGuardians();
        if (_guardians[msg.sender][guardianAddr].addr != address(0)) revert GuardianAlreadyExists();

        _guardians[msg.sender][guardianAddr] =
            Guardian({addr: guardianAddr, weight: weight, identityHash: identityHash});
        _guardianList[msg.sender].push(guardianAddr);
        cfg.guardianCount++;

        emit GuardianAdded(msg.sender, guardianAddr, weight);
    }

    /**
     * @notice Remove a guardian. Only callable by the account itself.
     * Cannot remove if it would make threshold unreachable.
     */
    function removeGuardian(address guardianAddr) external {
        AccountConfig storage cfg = _configs[msg.sender];
        if (!cfg.initialized) revert ModuleNotInitialized();
        if (_guardians[msg.sender][guardianAddr].addr == address(0)) revert GuardianNotFound();

        // Check threshold still reachable after removal
        uint256 removedWeight = _guardians[msg.sender][guardianAddr].weight;
        uint256 totalWeight = _totalGuardianWeight(msg.sender);
        require(totalWeight - removedWeight >= cfg.threshold, "Would make threshold unreachable");

        delete _guardians[msg.sender][guardianAddr];

        // Remove from list
        address[] storage list = _guardianList[msg.sender];
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i] == guardianAddr) {
                list[i] = list[list.length - 1];
                list.pop();
                break;
            }
        }
        cfg.guardianCount--;

        emit GuardianRemoved(msg.sender, guardianAddr);
    }

    /**
     * @notice Update the recovery threshold. Only callable by the account itself.
     */
    function setThreshold(uint256 newThreshold) external {
        AccountConfig storage cfg = _configs[msg.sender];
        if (!cfg.initialized) revert ModuleNotInitialized();
        if (newThreshold == 0) revert InvalidThreshold();

        uint256 totalWeight = _totalGuardianWeight(msg.sender);
        require(totalWeight >= newThreshold, "Threshold unreachable");

        cfg.threshold = newThreshold;
        emit ThresholdChanged(msg.sender, newThreshold);
    }

    // ─────────────────────────────────────────────────────────────
    // View helpers
    // ─────────────────────────────────────────────────────────────

    function getConfig(address account)
        external
        view
        returns (bool initialized, uint256 threshold, uint256 guardianCount)
    {
        AccountConfig storage cfg = _configs[account];
        return (cfg.initialized, cfg.threshold, cfg.guardianCount);
    }

    function getGuardian(address account, address guardianAddr)
        external
        view
        returns (address addr, uint256 weight, bytes32 identityHash)
    {
        Guardian storage g = _guardians[account][guardianAddr];
        return (g.addr, g.weight, g.identityHash);
    }

    function getGuardianList(address account) external view returns (address[] memory) {
        return _guardianList[account];
    }

    function getRecovery(address account)
        external
        view
        returns (
            bytes32 newCredentialId,
            uint256[2] memory newPubKey,
            uint256 initiatedAt,
            uint256 executeAfter,
            uint256 totalWeight,
            bool executed,
            bool cancelled,
            address initiator
        )
    {
        RecoveryRequest storage req = _recoveries[account];
        return (
            req.newCredentialId,
            req.newPubKey,
            req.initiatedAt,
            req.initiatedAt == 0 ? 0 : req.initiatedAt + RECOVERY_DELAY,
            req.totalWeight,
            req.executed,
            req.cancelled,
            req.initiator
        );
    }

    function hasApproved(address account, address guardian) external view returns (bool) {
        uint256 initiatedAt = _recoveries[account].initiatedAt;
        if (initiatedAt == 0) return false;
        return _approvals[account][initiatedAt][guardian];
    }

    function getCooldownRemaining(address account, address guardian) external view returns (uint256) {
        uint256 last = _lastApproval[account][guardian];
        if (last == 0) return 0;
        uint256 unlockAt = last + APPROVAL_COOLDOWN;
        if (block.timestamp >= unlockAt) return 0;
        return unlockAt - block.timestamp;
    }

    function getTotalGuardianWeight(address account) external view returns (uint256) {
        return _totalGuardianWeight(account);
    }

    // ─────────────────────────────────────────────────────────────
    // ERC-7579 introspection
    // ─────────────────────────────────────────────────────────────

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_EXECUTOR;
    }

    function isInitialized(address account) external view override returns (bool) {
        return _configs[account].initialized;
    }

    // ─────────────────────────────────────────────────────────────
    // Internal — recovery execution
    // ─────────────────────────────────────────────────────────────

    /**
     * @dev Execute the approved recovery: effects first, then ask the account (this module must be
     * an installed EXECUTOR) to call BiometricValidator.recoverCredential(newId, newPubKey).
     */
    function _executeRecovery(address account) internal {
        RecoveryRequest storage req = _recoveries[account];
        req.executed = true;

        bytes32 credId = req.newCredentialId;
        uint256[2] memory pk = req.newPubKey;
        emit RecoveryExecuted(account, credId);

        bytes memory call_ = abi.encodeWithSignature("recoverCredential(bytes32,uint256[2])", credId, pk);
        // ERC-7579 single exec is PACKED: target(20) || value(32) || calldata
        IERC7579Account(account)
            .executeFromExecutor(ModeLib.encodeSimpleSingle(), abi.encodePacked(biometricValidator, uint256(0), call_));
    }

    // ─────────────────────────────────────────────────────────────
    // Internal — helpers
    // ─────────────────────────────────────────────────────────────

    function _totalGuardianWeight(address account) internal view returns (uint256 total) {
        address[] storage list = _guardianList[account];
        for (uint256 i = 0; i < list.length; i++) {
            total += _guardians[account][list[i]].weight;
        }
    }
}
