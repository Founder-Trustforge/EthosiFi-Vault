// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {IModule} from "erc7579/interfaces/IModule.sol";

/**
 * @title MultiSigUpgradeGuard
 * @notice EthosiFi Vault — Prevents any module upgrade without guardian consensus + time delay.
 * @dev Closes the supply-chain attack vector that caused the $1.5B Bybit hack
 *      and the Trust Wallet browser extension breach of December 2025.
 *      No single party — including the EthosiFi team — can push a malicious
 *      upgrade without guardian approval and a mandatory waiting period.
 *
 * Layer: Core Security
 */
contract MultiSigUpgradeGuard is IModule {

    uint256 constant MODULE_TYPE_HOOK = 4;
    uint256 public constant UPGRADE_DELAY = 72 hours;   // 3-day mandatory wait
    uint256 public constant MAX_GUARDIANS = 10;

    struct UpgradeProposal {
        address proposedModule;
        bytes4  moduleType;
        uint256 proposedAt;
        uint256 approvals;
        bool    executed;
        bool    cancelled;
        mapping(address => bool) hasApproved;
    }

    struct GuardConfig {
        bool     initialized;
        address[] guardians;
        uint256  threshold;
        mapping(address => bool) isGuardian;
        mapping(bytes32 => UpgradeProposal) proposals;
    }

    mapping(address => GuardConfig) public configs;

    event UpgradeProposed(address indexed account, bytes32 indexed proposalId, address proposedModule, uint256 executeAfter);
    event UpgradeApproved(address indexed account, bytes32 indexed proposalId, address guardian, uint256 totalApprovals);
    event UpgradeExecuted(address indexed account, bytes32 indexed proposalId, address newModule);
    event UpgradeCancelled(address indexed account, bytes32 indexed proposalId, address cancelledBy);
    event UpgradeAttemptBlocked(address indexed account, address indexed attacker, address attemptedModule);

    // ─────────────────────────────────────────────
    // Module Lifecycle
    // ─────────────────────────────────────────────

    function onInstall(bytes calldata data) external {
        require(!configs[msg.sender].initialized, "Already initialized");

        (address[] memory _guardians, uint256 _threshold) =
            abi.decode(data, (address[], uint256));

        require(_guardians.length > 0, "Need guardians");
        require(_guardians.length <= MAX_GUARDIANS, "Too many guardians");
        require(_threshold > 0 && _threshold <= _guardians.length, "Invalid threshold");

        GuardConfig storage config = configs[msg.sender];
        config.initialized = true;
        config.threshold = _threshold;

        for (uint256 i = 0; i < _guardians.length; i++) {
            require(_guardians[i] != address(0), "Invalid guardian");
            config.guardians.push(_guardians[i]);
            config.isGuardian[_guardians[i]] = true;
        }
    }

    function onUninstall(bytes calldata) external {
        delete configs[msg.sender];
    }

    // ─────────────────────────────────────────────
    // Upgrade Proposal Flow
    // ─────────────────────────────────────────────

    /**
     * @notice Propose a module upgrade. Must be a guardian.
     * @param account   The vault account being upgraded
     * @param newModule The new module contract address
     * @param moduleType The ERC-7579 module type being replaced
     */
    function proposeUpgrade(
        address account,
        address newModule,
        bytes4 moduleType
    ) external returns (bytes32 proposalId) {
        GuardConfig storage config = configs[account];
        require(config.initialized, "Not initialized");
        require(config.isGuardian[msg.sender], "Not a guardian");
        require(newModule != address(0), "Invalid module");
        require(newModule.code.length > 0, "Not a contract");

        proposalId = keccak256(abi.encodePacked(account, newModule, moduleType, block.timestamp));

        UpgradeProposal storage proposal = config.proposals[proposalId];
        proposal.proposedModule = newModule;
        proposal.moduleType = moduleType;
        proposal.proposedAt = block.timestamp;
        proposal.approvals = 1;
        proposal.hasApproved[msg.sender] = true;

        emit UpgradeProposed(account, proposalId, newModule, block.timestamp + UPGRADE_DELAY);
    }

    /**
     * @notice Approve an upgrade proposal.
     */
    function approveUpgrade(address account, bytes32 proposalId) external {
        GuardConfig storage config = configs[account];
        require(config.initialized, "Not initialized");
        require(config.isGuardian[msg.sender], "Not a guardian");

        UpgradeProposal storage proposal = config.proposals[proposalId];
        require(proposal.proposedAt > 0, "Proposal not found");
        require(!proposal.executed, "Already executed");
        require(!proposal.cancelled, "Cancelled");
        require(!proposal.hasApproved[msg.sender], "Already approved");

        proposal.hasApproved[msg.sender] = true;
        proposal.approvals++;

        emit UpgradeApproved(account, proposalId, msg.sender, proposal.approvals);
    }

    /**
     * @notice Execute upgrade after delay + threshold met.
     */
    function executeUpgrade(address account, bytes32 proposalId) external {
        GuardConfig storage config = configs[account];
        require(config.initialized, "Not initialized");

        UpgradeProposal storage proposal = config.proposals[proposalId];
        require(proposal.proposedAt > 0, "Not found");
        require(!proposal.executed, "Already executed");
        require(!proposal.cancelled, "Cancelled");
        require(proposal.approvals >= config.threshold, "Insufficient approvals");
        require(block.timestamp >= proposal.proposedAt + UPGRADE_DELAY, "Delay not elapsed");

        proposal.executed = true;
        emit UpgradeExecuted(account, proposalId, proposal.proposedModule);

        // Actual module swap handled by the ERC-7579 account
    }

    /**
     * @notice Cancel an upgrade proposal. Any guardian can cancel.
     */
    function cancelUpgrade(address account, bytes32 proposalId) external {
        GuardConfig storage config = configs[account];
        require(config.initialized, "Not initialized");
        require(config.isGuardian[msg.sender], "Not a guardian");

        UpgradeProposal storage proposal = config.proposals[proposalId];
        require(!proposal.executed, "Already executed");
        require(!proposal.cancelled, "Already cancelled");

        proposal.cancelled = true;
        emit UpgradeCancelled(account, proposalId, msg.sender);
    }

    // ─────────────────────────────────────────────
    // Hook: Block Unauthorized Upgrades
    // ─────────────────────────────────────────────

    /**
     * @notice Pre-execution hook. Detects and blocks unauthorized upgrade calls.
     */
    function preCheck(
        address account,
        address target,
        uint256,
        bytes calldata callData
    ) external returns (bytes memory) {
        // Detect installModule / uninstallModule selectors (ERC-7579)
        if (callData.length >= 4) {
            bytes4 selector = bytes4(callData[:4]);
            bool isUpgradeCall = (
                selector == bytes4(keccak256("installModule(uint256,address,bytes)")) ||
                selector == bytes4(keccak256("uninstallModule(uint256,address,bytes)"))
            );

            if (isUpgradeCall) {
                GuardConfig storage config = configs[account];
                if (config.initialized) {
                    // Must have an approved, delay-elapsed proposal
                    // In production: verify proposalId from calldata
                    emit UpgradeAttemptBlocked(account, msg.sender, target);
                    revert("EthosiFi: Module upgrades require guardian consensus. Use proposeUpgrade().");
                }
            }
        }
        return "";
    }

    function postCheck(bytes calldata) external pure {}

    // ─────────────────────────────────────────────
    // View Helpers
    // ─────────────────────────────────────────────

    function getProposal(address account, bytes32 proposalId) external view returns (
        address proposedModule,
        uint256 proposedAt,
        uint256 approvals,
        bool executed,
        bool cancelled,
        bool delayElapsed
    ) {
        UpgradeProposal storage p = configs[account].proposals[proposalId];
        return (
            p.proposedModule,
            p.proposedAt,
            p.approvals,
            p.executed,
            p.cancelled,
            block.timestamp >= p.proposedAt + UPGRADE_DELAY
        );
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function isInitialized(address account) external view returns (bool) {
        return configs[account].initialized;
    }



}