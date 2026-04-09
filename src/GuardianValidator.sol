// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {IValidator} from "erc7579/interfaces/IModule.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ReentrancyGuard} from "solady/utils/ReentrancyGuard.sol";
import {IERC7579Account} from "erc7579/interfaces/IERC7579Account.sol";

/**
 * @title  GuardianValidator
 * @author EthosiFi (founder@ethosifi.com)
 * @notice ERC-7579 validator module — weighted social recovery with time delays
 *         for the EthosiFi Vault.
 *
 *         Recovery model
 *         ──────────────
 *         • Guardians are assigned weights (e.g. family=3, friend=1, hardware key=5).
 *         • A recovery is initiated by ANY guardian or the account owner.
 *         • Other guardians approve during the RECOVERY_DELAY window.
 *         • Once total weight ≥ threshold AND delay has elapsed → execution is unlocked.
 *         • Any single guardian can cancel during the delay (veto power).
 *         • Execution rotates the account's validator module (BiometricValidator credential).
 *         • Each guardian has a per-approval cooldown to prevent rapid re-voting.
 *         • Only one active recovery per account at a time.
 *
 *         This validator does NOT validate standard UserOps (always returns FAILED).
 *         It is a recovery-only module — it is not in the hot path.
 *
 * @dev    BSL 1.1 — non-commercial use free; commercial license: founder@ethosifi.com
 *         Converts to GPL-3.0 on 2029-01-01.
 */
contract GuardianValidator is IValidator, ReentrancyGuard {

    // ─────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────

    uint256 public constant MODULE_TYPE_VALIDATOR = 1;

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
        bytes32 identityHash;   // off-chain identity commitment (e.g. keccak256(email))
    }

    struct AccountConfig {
        bool       initialized;
        uint256    threshold;   // minimum total weight to approve recovery
        uint256    guardianCount;
    }

    struct RecoveryRequest {
        bytes32    newCredentialHash;   // keccak256(credentialId ++ pubKey) to install
        address    newValidator;        // address of the new validator module (optional)
        bytes      newValidatorData;    // install data for the new validator module
        uint256    initiatedAt;
        uint256    totalWeight;
        bool       executed;
        bool       cancelled;
        address    initiator;
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
        address indexed account,
        address indexed initiator,
        bytes32 indexed newCredentialHash,
        uint256 executeAfter
    );
    event GuardianApproved(
        address indexed account,
        address indexed guardian,
        uint256 weight,
        uint256 totalWeight
    );
    event RecoveryExecuted(address indexed account, bytes32 indexed newCredentialHash);
    event RecoveryCancelled(address indexed account, address indexed cancelledBy);
    event GuardianAdded(address indexed account, address indexed guardian, uint256 weight);
    event GuardianRemoved(address indexed account, address indexed guardian);
    event ThresholdChanged(address indexed account, uint256 newThreshold);

    // ─────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────

    error AlreadyInitialized();
    error NotInitialized();
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
     * @param  data ABI-encoded (Guardian[] guardians, uint256 threshold)
     *              Guardian: (address addr, uint256 weight, bytes32 identityHash)
     *              threshold: minimum total weight required for recovery approval.
     */
    function onInstall(bytes calldata data) external override {
        if (_configs[msg.sender].initialized) revert AlreadyInitialized();

        (Guardian[] memory initialGuardians, uint256 _threshold) =
            abi.decode(data, (Guardian[], uint256));

        if (initialGuardians.length == 0)             revert InvalidGuardian();
        if (initialGuardians.length > MAX_GUARDIANS)  revert TooManyGuardians();
        if (_threshold == 0)                          revert InvalidThreshold();

        uint256 totalWeight = 0;

        for (uint256 i = 0; i < initialGuardians.length; i++) {
            Guardian memory g = initialGuardians[i];
            if (g.addr == address(0))                         revert ZeroAddress();
            if (g.weight == 0)                                revert InvalidWeight();
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

        _configs[msg.sender] = AccountConfig({
            initialized:   true,
            threshold:     _threshold,
            guardianCount: initialGuardians.length
        });
    }

    /**
     * @notice Uninstall — clears all guardian state.
     *         If a recovery is pending it is implicitly abandoned.
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
    // ERC-7579 Validation
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice This module does NOT validate standard UserOps.
     *         It is a recovery-only module. Always returns FAILED.
     *         The TimeLockValidator handles normal UserOp validation.
     */
    function validateUserOp(
        PackedUserOperation calldata,
        bytes32,
        uint256
    ) external pure override returns (uint256) {
        return 1; // SIG_VALIDATION_FAILED — intentional
    }

    /**
     * @notice EIP-1271 — not supported by this module.
     */
    function isValidSignatureWithSender(
        address,
        bytes32,
        bytes calldata
    ) external pure override returns (bytes4) {
        return 0xffffffff;
    }

    // ─────────────────────────────────────────────────────────────
    // Recovery flow
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice Initiate a recovery request.
     *         Can be called by any guardian OR the account itself.
     *
     * @param  account            The account to recover.
     * @param  newCredentialHash  keccak256 of the new credential to install
     *                            (e.g. keccak256(abi.encode(credentialId, pubKeyX, pubKeyY))).
     * @param  newValidator       Address of new validator module to install (address(0) = keep existing).
     * @param  newValidatorData   Install calldata for the new validator module.
     */
    function initiateRecovery(
        address account,
        bytes32 newCredentialHash,
        address newValidator,
        bytes calldata newValidatorData
    ) external {
        AccountConfig storage cfg = _configs[account];
        if (!cfg.initialized) revert NotInitialized();

        // Only a guardian or the account itself may initiate
        bool callerIsGuardian = _guardians[account][msg.sender].addr != address(0);
        bool callerIsAccount  = msg.sender == account;
        if (!callerIsGuardian && !callerIsAccount) revert NotGuardianOrOwner();

        RecoveryRequest storage req = _recoveries[account];
        if (req.initiatedAt > 0 && !req.executed && !req.cancelled) revert RecoveryPending();

        // Reset any previous (executed or cancelled) request
        delete _recoveries[account];

        RecoveryRequest storage newReq = _recoveries[account];
        newReq.newCredentialHash = newCredentialHash;
        newReq.newValidator      = newValidator;
        newReq.newValidatorData  = newValidatorData;
        newReq.initiatedAt       = block.timestamp;
        newReq.initiator         = msg.sender;

        // If initiator is a guardian, count their weight immediately
        if (callerIsGuardian) {
            Guardian storage g = _guardians[account][msg.sender];
            _approvals[account][block.timestamp][msg.sender] = true;
            _lastApproval[account][msg.sender] = block.timestamp;
            newReq.totalWeight += g.weight;
            emit GuardianApproved(account, msg.sender, g.weight, newReq.totalWeight);
        }

        emit RecoveryInitiated(account, msg.sender, newCredentialHash, block.timestamp + RECOVERY_DELAY);
    }

    /**
     * @notice Guardian approves the active recovery request.
     * @param  account  The account being recovered.
     */
    function approveRecovery(address account) external nonReentrant {
        AccountConfig storage cfg = _configs[account];
        if (!cfg.initialized) revert NotInitialized();

        Guardian storage g = _guardians[account][msg.sender];
        if (g.addr == address(0)) revert NotGuardian();

        RecoveryRequest storage req = _recoveries[account];
        if (req.initiatedAt == 0)  revert NoRecoveryActive();
        if (req.executed)          revert AlreadyExecuted();
        if (req.cancelled)         revert AlreadyCancelled();

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
        if (req.totalWeight >= cfg.threshold &&
            block.timestamp >= req.initiatedAt + RECOVERY_DELAY)
        {
            _executeRecovery(account);
        }
    }

    /**
     * @notice Execute recovery after delay has elapsed and threshold is met.
     *         Anyone may call this once conditions are satisfied (trustless execution).
     * @param  account  The account being recovered.
     */
    function executeRecovery(address account) external nonReentrant {
        AccountConfig storage cfg = _configs[account];
        if (!cfg.initialized) revert NotInitialized();

        RecoveryRequest storage req = _recoveries[account];
        if (req.initiatedAt == 0)                            revert NoRecoveryActive();
        if (req.executed)                                    revert AlreadyExecuted();
        if (req.cancelled)                                   revert AlreadyCancelled();
        if (req.totalWeight < cfg.threshold)                 revert InsufficientWeight();
        if (block.timestamp < req.initiatedAt + RECOVERY_DELAY) revert DelayNotElapsed();

        _executeRecovery(account);
    }

    /**
     * @notice Cancel an active recovery request.
     *         Any guardian OR the account itself can cancel during the delay window.
     * @param  account  The account whose recovery is being cancelled.
     */
    function cancelRecovery(address account) external {
        AccountConfig storage cfg = _configs[account];
        if (!cfg.initialized) revert NotInitialized();

        bool callerIsGuardian = _guardians[account][msg.sender].addr != address(0);
        bool callerIsAccount  = msg.sender == account;
        if (!callerIsGuardian && !callerIsAccount) revert NotGuardianOrOwner();

        RecoveryRequest storage req = _recoveries[account];
        if (req.initiatedAt == 0) revert NoRecoveryActive();
        if (req.executed)         revert CannotCancelExecuted();
        if (req.cancelled)        revert AlreadyCancelled();

        req.cancelled = true;
        emit RecoveryCancelled(account, msg.sender);
    }

    // ─────────────────────────────────────────────────────────────
    // Guardian management (account-only)
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice Add a new guardian. Only callable by the account itself.
     */
    function addGuardian(
        address guardianAddr,
        uint256 weight,
        bytes32 identityHash
    ) external {
        AccountConfig storage cfg = _configs[msg.sender];
        if (!cfg.initialized) revert NotInitialized();
        if (guardianAddr == address(0)) revert ZeroAddress();
        if (weight == 0) revert InvalidWeight();
        if (cfg.guardianCount >= MAX_GUARDIANS) revert TooManyGuardians();
        if (_guardians[msg.sender][guardianAddr].addr != address(0)) revert GuardianAlreadyExists();

        _guardians[msg.sender][guardianAddr] = Guardian({
            addr:         guardianAddr,
            weight:       weight,
            identityHash: identityHash
        });
        _guardianList[msg.sender].push(guardianAddr);
        cfg.guardianCount++;

        emit GuardianAdded(msg.sender, guardianAddr, weight);
    }

    /**
     * @notice Remove a guardian. Only callable by the account itself.
     *         Cannot remove if it would make threshold unreachable.
     */
    function removeGuardian(address guardianAddr) external {
        AccountConfig storage cfg = _configs[msg.sender];
        if (!cfg.initialized) revert NotInitialized();
        if (_guardians[msg.sender][guardianAddr].addr == address(0)) revert GuardianNotFound();

        // Check threshold still reachable after removal
        uint256 removedWeight = _guardians[msg.sender][guardianAddr].weight;
        uint256 totalWeight   = _totalGuardianWeight(msg.sender);
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
        if (!cfg.initialized) revert NotInitialized();
        if (newThreshold == 0) revert InvalidThreshold();

        uint256 totalWeight = _totalGuardianWeight(msg.sender);
        require(totalWeight >= newThreshold, "Threshold unreachable");

        cfg.threshold = newThreshold;
        emit ThresholdChanged(msg.sender, newThreshold);
    }

    // ─────────────────────────────────────────────────────────────
    // View helpers
    // ─────────────────────────────────────────────────────────────

    function getConfig(address account) external view returns (
        bool   initialized,
        uint256 threshold,
        uint256 guardianCount
    ) {
        AccountConfig storage cfg = _configs[account];
        return (cfg.initialized, cfg.threshold, cfg.guardianCount);
    }

    function getGuardian(address account, address guardianAddr) external view returns (
        address addr,
        uint256 weight,
        bytes32 identityHash
    ) {
        Guardian storage g = _guardians[account][guardianAddr];
        return (g.addr, g.weight, g.identityHash);
    }

    function getGuardianList(address account) external view returns (address[] memory) {
        return _guardianList[account];
    }

    function getRecovery(address account) external view returns (
        bytes32 newCredentialHash,
        address newValidator,
        uint256 initiatedAt,
        uint256 executeAfter,
        uint256 totalWeight,
        bool    executed,
        bool    cancelled,
        address initiator
    ) {
        RecoveryRequest storage req = _recoveries[account];
        return (
            req.newCredentialHash,
            req.newValidator,
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

    function getCooldownRemaining(address account, address guardian)
        external view returns (uint256)
    {
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
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address account) external view override returns (bool) {
        return _configs[account].initialized;
    }

    // ─────────────────────────────────────────────────────────────
    // Internal — recovery execution
    // ─────────────────────────────────────────────────────────────

    /**
     * @dev  Execute the approved recovery:
     *       1. Mark as executed (effects before interactions).
     *       2. If a new validator module is specified, call the account to
     *          uninstall the old BiometricValidator and install the new one.
     *       3. If no new module, call the existing BiometricValidator to
     *          update the credential (via a known interface).
     *       4. Emit RecoveryExecuted.
     *
     * @dev  The account must have authorised this module as an executor
     *       (ERC-7579 executor permission) to call executeFromExecutor.
     */
    function _executeRecovery(address account) internal {
        RecoveryRequest storage req = _recoveries[account];

        // Effects first — reentrancy safe
        req.executed = true;

        bytes32 credHash     = req.newCredentialHash;
        address newValidator = req.newValidator;
        bytes memory installData = req.newValidatorData;

        emit RecoveryExecuted(account, credHash);

        if (newValidator != address(0)) {
            // Full validator rotation: uninstall current BiometricValidator, install new one.
            // ERC-7579: account.uninstallModule(MODULE_TYPE_VALIDATOR, oldValidator, "")
            //           account.installModule(MODULE_TYPE_VALIDATOR, newValidator, installData)
            //
            // Encoded as a batch execute via executeFromExecutor.
            bytes memory uninstallCall = abi.encodeWithSignature(
                "uninstallModule(uint256,address,bytes)",
                1,           // MODULE_TYPE_VALIDATOR
                address(0),  // current validator — account resolves this internally
                ""
            );
            bytes memory installCall = abi.encodeWithSignature(
                "installModule(uint256,address,bytes)",
                1,
                newValidator,
                installData
            );

            // Batch: [uninstall, install]
            bytes memory batchData = abi.encode(
                _buildExecution(account, 0, uninstallCall),
                _buildExecution(account, 0, installCall)
            );

            IERC7579Account(account).executeFromExecutor(
                0x01, // ModeCode: batch call
                batchData
            );
        } else {
            // Credential-only rotation: call the existing validator module
            // to update the registered credential via a known selector.
            // The BiometricValidator must expose: rotateCredential(bytes32 credentialHash)
            bytes memory rotateCall = abi.encodeWithSignature(
                "rotateCredential(bytes32)",
                credHash
            );

            IERC7579Account(account).executeFromExecutor(
                0x00, // ModeCode: single call
                abi.encode(account, uint256(0), rotateCall)
            );
        }
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

    function _buildExecution(
        address target,
        uint256 value,
        bytes memory callData
    ) internal pure returns (bytes memory) {
        return abi.encode(target, value, callData);
    }
}
