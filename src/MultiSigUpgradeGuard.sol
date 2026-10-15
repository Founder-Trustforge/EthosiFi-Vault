// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {RouterGated} from "./lib/RouterGated.sol";
import {IModule} from "erc7579/interfaces/IERC7579Module.sol";

/**
 * @title MultiSigUpgradeGuard
 * @notice EthosiFi Vault — Prevents any module upgrade without guardian consensus + time delay.
 * @dev Closes the supply-chain attack vector that caused the $1.5B Bybit hack
 * and the Trust Wallet browser extension breach of December 2025.
 * No single party — including the EthosiFi team — can push a malicious
 * upgrade without guardian approval and a mandatory waiting period.
 *
 * Layer: Core Security
 */
contract MultiSigUpgradeGuard is IModule, RouterGated {
    constructor(address router_) RouterGated(router_) {}

    uint256 constant MODULE_TYPE_HOOK = 4;
    uint256 public constant UPGRADE_DELAY = 72 hours; // 3-day mandatory wait
    uint256 public constant MAX_GUARDIANS = 10;

    struct UpgradeProposal {
        address proposedModule;
        bytes4 moduleType;
        uint256 proposedAt;
        uint256 approvals;
        bool executed;
        bool cancelled;
        mapping(address => bool) hasApproved;
    }

    struct GuardConfig {
        bool initialized;
        address[] guardians;
        uint256 threshold;
        mapping(address => bool) isGuardian;
        mapping(bytes32 => UpgradeProposal) proposals;
    }

    mapping(address => GuardConfig) public configs;

    // [FIXED] preCheck previously reverted on EVERY installModule/uninstallModule
    // call once this guard was initialized, with no path to ever let an
    // approved, delay-elapsed upgrade through (the code comment even admitted
    // "In production: verify proposalId from calldata" was never implemented).
    // That's fail-safe against attackers but also permanently blocks every
    // legitimate upgrade — the propose/approve/execute flow above was
    // disconnected from the hook that's supposed to gate the real call.
    // Fixed via a one-time execution grant: executeUpgrade() records exactly
    // which (moduleType, module) it approved, and preCheck decodes the real
    // installModule/uninstallModule calldata and only lets the call through
    // if it matches an unexpired, unconsumed grant — then consumes it so it
    // can't be reused for a second, different call.
    struct ExecutionGrant {
        bytes4 moduleType;
        address module;
        uint256 expiresAt;
    }

    uint256 public constant GRANT_VALIDITY = 1 hours;
    mapping(address => ExecutionGrant) public pendingExecution;

    event UpgradeProposed(
        address indexed account, bytes32 indexed proposalId, address proposedModule, uint256 executeAfter
    );
    event UpgradeApproved(
        address indexed account, bytes32 indexed proposalId, address guardian, uint256 totalApprovals
    );
    event UpgradeExecuted(address indexed account, bytes32 indexed proposalId, address newModule);
    event UpgradeCancelled(address indexed account, bytes32 indexed proposalId, address cancelledBy);
    event UpgradeAttemptBlocked(address indexed account, address indexed attacker, address attemptedModule);

    // ─────────────────────────────────────────────
    // Module Lifecycle
    // ─────────────────────────────────────────────

    function onInstall(bytes calldata data) external {
        require(!configs[msg.sender].initialized, "Already initialized");

        (address[] memory _guardians, uint256 _threshold) = abi.decode(data, (address[], uint256));

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
     * @param account The vault account being upgraded
     * @param newModule The new module contract address
     * @param moduleType The ERC-7579 module type being replaced
     */
    function proposeUpgrade(address account, address newModule, bytes4 moduleType)
        external
        returns (bytes32 proposalId)
    {
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

        // Grant a single, time-boxed window for the actual installModule/
        // uninstallModule call (submitted separately by the account/relayer)
        // to pass preCheck below. Actual module swap still happens via the
        // account's own execute() path — this only authorizes preCheck to
        // let that specific call through instead of always reverting it.
        pendingExecution[account] = ExecutionGrant({
            moduleType: proposal.moduleType,
            module: proposal.proposedModule,
            expiresAt: block.timestamp + GRANT_VALIDITY
        });
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
    // Called by EthosiHookRouter (which the account calls on execute / executeFromExecutor /
    // installModule / uninstallModule). For module-management calls the router passes
    // target = account and callData = the full msg.data. `account` is trusted because only
    // the router can call this (RouterGated) and the router only forwards its own caller.
    function preCheck(address account, address target, uint256, bytes calldata callData)
        external
        onlyRouter
        returns (bytes memory)
    {
        // Detect installModule / uninstallModule selectors (ERC-7579)
        if (callData.length >= 4) {
            bytes4 selector = bytes4(callData[:4]);
            bool isUpgradeCall =
                (selector == bytes4(keccak256("installModule(uint256,address,bytes)"))
                    || selector == bytes4(keccak256("uninstallModule(uint256,address,bytes)")));

            if (isUpgradeCall) {
                GuardConfig storage config = configs[account];
                if (config.initialized) {
                    // installModule/uninstallModule(uint256 moduleTypeId, address module, bytes initData)
                    bool decodeOk = true;
                    uint256 moduleTypeId;
                    address module;
                    if (callData.length >= 4 + 64) {
                        (moduleTypeId, module) = abi.decode(callData[4:4 + 64], (uint256, address));
                    } else {
                        decodeOk = false;
                    }

                    ExecutionGrant memory grant = pendingExecution[account];
                    // NOTE: proposeUpgrade()'s `moduleType` param is typed
                    // bytes4 (an existing interface choice, not changed here)
                    // while ERC-7579's installModule takes a uint256
                    // moduleTypeId. Comparing via bytes4(uint32(moduleTypeId))
                    // assumes callers of proposeUpgrade pass moduleType using
                    // that same low-bits encoding (e.g. bytes4(uint32(1)) for
                    // TYPE_VALIDATOR) — verify this matches how VaultFactory /
                    // off-chain tooling actually calls proposeUpgrade before
                    // relying on this in production.
                    bool grantValid = decodeOk && grant.expiresAt > block.timestamp && grant.module == module
                        && grant.moduleType == bytes4(uint32(moduleTypeId));

                    if (!grantValid) {
                        emit UpgradeAttemptBlocked(account, msg.sender, target);
                        revert("EthosiFi: Module upgrades require guardian consensus. Use proposeUpgrade().");
                    }

                    // One-time use — consume the grant so it can't authorize
                    // a second, different installModule/uninstallModule call.
                    delete pendingExecution[account];
                }
            }
        }
        return "";
    }

    function postCheck(bytes calldata) external pure {}

    // ─────────────────────────────────────────────
    // View Helpers
    // ─────────────────────────────────────────────

    function getProposal(address account, bytes32 proposalId)
        external
        view
        returns (
            address proposedModule,
            uint256 proposedAt,
            uint256 approvals,
            bool executed,
            bool cancelled,
            bool delayElapsed
        )
    {
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
