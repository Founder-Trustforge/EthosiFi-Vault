// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {IModule} from "erc7579/interfaces/IModule.sol";

/**
 * @title EmergencyFreeze
 * @notice EthosiFi Vault — Instant panic button for any authorized guardian.
 * @dev Any guardian can freeze ALL outgoing transactions in a single call.
 *      No delay. No consensus. Activates in one block.
 *      Requires guardian multi-sig consensus to unfreeze.
 *      This closes the attack window the moment suspicious activity is detected.
 *
 * Layer: Core Security
 */
contract EmergencyFreeze is IModule {

    uint256 constant MODULE_TYPE_HOOK = 4;

    struct FreezeConfig {
        bool initialized;
        bool frozen;
        address[] guardians;
        uint256 unfreezeThreshold;     // Guardian votes needed to unfreeze
        uint256 frozenAt;
        address frozenBy;
        uint256 unfreezeVotes;
        uint256 autoExpiry;            // Optional: freeze auto-expires after X seconds (0 = never)
        mapping(address => bool) isGuardian;
        mapping(address => bool) hasVotedToUnfreeze;
    }

    mapping(address => FreezeConfig) public configs;

    event VaultFrozen(address indexed account, address indexed guardian, uint256 timestamp);
    event VaultUnfreezeVote(address indexed account, address indexed guardian, uint256 votesTotal, uint256 threshold);
    event VaultUnfrozen(address indexed account, uint256 timestamp);
    event GuardianAdded(address indexed account, address indexed guardian);
    event GuardianRemoved(address indexed account, address indexed guardian);

    // ─────────────────────────────────────────────
    // Module Lifecycle
    // ─────────────────────────────────────────────

    function onInstall(bytes calldata data) external override {
        require(!configs[msg.sender].initialized, "Already initialized");

        (address[] memory _guardians, uint256 _threshold, uint256 _autoExpiry) =
            abi.decode(data, (address[], uint256, uint256));

        require(_guardians.length > 0, "Need at least one guardian");
        require(_threshold > 0 && _threshold <= _guardians.length, "Invalid threshold");

        FreezeConfig storage config = configs[msg.sender];
        config.initialized = true;
        config.unfreezeThreshold = _threshold;
        config.autoExpiry = _autoExpiry;

        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != address(0), "Invalid guardian");
            config.guardians.push(_guardians[i]);
            config.isGuardian[_guardians[i]] = true;
            emit GuardianAdded(msg.sender, _guardians[i]);
        }
    }

    function onUninstall(bytes calldata) external override {
        FreezeConfig storage config = configs[msg.sender];
        require(!config.frozen, "Cannot uninstall while frozen");
        delete configs[msg.sender];
    }

    // ─────────────────────────────────────────────
    // Core: Freeze & Unfreeze
    // ─────────────────────────────────────────────

    /**
     * @notice Instantly freeze all outgoing transactions. One guardian call. One block.
     * @dev No consensus required to freeze — speed is everything in an attack.
     */
    function freeze(address account) external {
        FreezeConfig storage config = configs[account];
        require(config.initialized, "Not initialized");
        require(config.isGuardian[msg.sender], "Not a guardian");
        require(!config.frozen, "Already frozen");

        config.frozen = true;
        config.frozenAt = block.timestamp;
        config.frozenBy = msg.sender;
        config.unfreezeVotes = 0;

        // Reset unfreeze votes
        for (uint256 i = 0; i < config.guardians.length; i++) {
            config.hasVotedToUnfreeze[config.guardians[i]] = false;
        }

        emit VaultFrozen(account, msg.sender, block.timestamp);
    }

    /**
     * @notice Vote to unfreeze. Requires multi-sig consensus.
     * @dev Multiple guardians must agree before unfreezing.
     *      This prevents a single malicious guardian from unfreezing after a legitimate freeze.
     */
    function voteToUnfreeze(address account) external {
        FreezeConfig storage config = configs[account];
        require(config.initialized, "Not initialized");
        require(config.isGuardian[msg.sender], "Not a guardian");
        require(config.frozen, "Not frozen");
        require(!config.hasVotedToUnfreeze[msg.sender], "Already voted");

        // Check auto-expiry
        if (config.autoExpiry > 0 && block.timestamp > config.frozenAt + config.autoExpiry) {
            _unfreeze(account);
            return;
        }

        config.hasVotedToUnfreeze[msg.sender] = true;
        config.unfreezeVotes++;

        emit VaultUnfreezeVote(account, msg.sender, config.unfreezeVotes, config.unfreezeThreshold);

        if (config.unfreezeVotes >= config.unfreezeThreshold) {
            _unfreeze(account);
        }
    }

    function _unfreeze(address account) internal {
        FreezeConfig storage config = configs[account];
        config.frozen = false;
        config.frozenAt = 0;
        config.frozenBy = address(0);
        config.unfreezeVotes = 0;
        emit VaultUnfrozen(account, block.timestamp);
    }

    // ─────────────────────────────────────────────
    // Hook: Called Before Every Transaction
    // ─────────────────────────────────────────────

    /**
     * @notice Pre-execution hook. Blocks ALL transactions when vault is frozen.
     */
    function preCheck(
        address account,
        address,
        uint256,
        bytes calldata
    ) external view returns (bytes memory) {
        FreezeConfig storage config = configs[account];
        if (!config.initialized) return "";

        // Auto-expiry check
        if (config.frozen && config.autoExpiry > 0) {
            if (block.timestamp > config.frozenAt + config.autoExpiry) {
                return ""; // Expired freeze — allow
            }
        }

        require(!config.frozen, "EthosiFi: Vault is frozen. Contact your guardians.");
        return "";
    }

    function postCheck(bytes calldata) external pure {}

    // ─────────────────────────────────────────────
    // View Helpers
    // ─────────────────────────────────────────────

    function isFrozen(address account) external view returns (bool) {
        return configs[account].frozen;
    }

    function getFreezeInfo(address account) external view returns (
        bool frozen,
        address frozenBy,
        uint256 frozenAt,
        uint256 unfreezeVotes,
        uint256 unfreezeThreshold
    ) {
        FreezeConfig storage config = configs[account];
        return (config.frozen, config.frozenBy, config.frozenAt, config.unfreezeVotes, config.unfreezeThreshold);
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function isInitialized(address account) external view override returns (bool) {
        return configs[account].initialized;
    }
}

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure override returns (bytes4) {
        return 0xffffffff;
    }
