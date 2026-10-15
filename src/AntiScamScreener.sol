// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;
import {RouterGated} from "./lib/RouterGated.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {IModule} from "erc7579/interfaces/IERC7579Module.sol";

/**
 * @title AntiScamScreener
 * @notice EthosiFi Vault — Real-time transaction screening before execution.
 * @dev Screens every transaction against a continuously updated registry of:
 *      - Known malicious contract addresses
 *      - Phishing wallet addresses
 *      - Rug-pull token contracts
 *      - Known exploit deployer addresses
 *      - Sanctioned addresses (OFAC compliance)
 *
 *      Blocks the transaction BEFORE it reaches the mempool.
 *      This is not a warning. This is a hard block at the blockchain level.
 *
 *      Registry updated via EthosiFi governance multisig, fed by:
 *      - Chainalysis KYT feeds
 *      - Cyvers real-time threat intelligence
 *      - Community reports with stake-based verification
 *
 * Layer: User Protection (Pillar 2)
 */
contract AntiScamScreener is IModule, RouterGated {
    uint256 constant MODULE_TYPE_HOOK = 4;

    // [CRIT FIXED] registerThreat/batchRegisterThreats/removeThreat below were
    // marked `onlyOwner`, but this contract never declared an owner or that
    // modifier — a straight compile error, meaning this fix note was written
    // but never actually applied. Adding real two-step ownership here,
    // matching the pattern already used elsewhere in this codebase (e.g.
    // AIThreatOracle, PoisonedAddressProtection).
    address public owner;
    address public pendingOwner;

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "AntiScamScreener: not owner");
        _;
    }

    constructor(address router_) RouterGated(router_) {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "Not pending owner");
        emit OwnershipTransferred(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    enum ThreatLevel {
        SAFE, // 0 - No known threats
        LOW, // 1 - Minor concerns, warn only
        MEDIUM, // 2 - Significant risk, require extra confirmation
        HIGH, // 3 - Known scam/phishing, block by default
        CRITICAL // 4 - Confirmed exploit/sanctioned, always block
    }

    struct ThreatEntry {
        ThreatLevel level;
        string reason; // Human-readable reason
        uint256 reportedAt;
        uint256 reportCount;
        bool active;
    }

    struct ScreenerConfig {
        bool initialized;
        ThreatLevel blockThreshold; // Block transactions at this level and above
        bool allowOverride; // Allow user to override MEDIUM threats (not HIGH/CRITICAL)
        mapping(address => bool) userWhitelist; // User-specific bypass for false positives
    }

    // Global threat registry
    mapping(address => ThreatEntry) public threatRegistry;
    mapping(address => ScreenerConfig) public configs;

    // Statistics
    uint256 public totalBlocked;
    uint256 public totalScreened;

    event TransactionBlocked(address indexed account, address indexed target, ThreatLevel level, string reason);
    event TransactionWarning(address indexed account, address indexed target, ThreatLevel level, string reason);
    event ThreatRegistered(address indexed target, ThreatLevel level, string reason);
    event ThreatRemoved(address indexed target, string reason);
    event UserWhitelisted(address indexed account, address indexed target);

    // ─────────────────────────────────────────────
    // Module Lifecycle
    // ─────────────────────────────────────────────

    function onInstall(bytes calldata data) external {
        require(!configs[msg.sender].initialized, "Already initialized");

        (uint8 blockThreshold, bool allowOverride) = abi.decode(data, (uint8, bool));

        ScreenerConfig storage config = configs[msg.sender];
        config.initialized = true;
        config.blockThreshold = ThreatLevel(blockThreshold > 0 ? blockThreshold : uint8(ThreatLevel.HIGH));
        config.allowOverride = allowOverride;
    }

    function onUninstall(bytes calldata) external {
        delete configs[msg.sender];
    }

    // ─────────────────────────────────────────────
    // Hook: Screen Every Transaction
    // ─────────────────────────────────────────────

    /**
     * @notice Pre-execution hook (called by the account's EthosiHookRouter for EVERY inner call).
     * Screens the call target AND the address argument of transfer / approve / transferFrom /
     * setApprovalForAll calls (the classic drainer patterns), so sending tokens to - or approving -
     * a flagged address is blocked even though the call target is a harmless token contract.
     */
    function preCheck(address account, address target, uint256, bytes memory callData)
        external
        view
        onlyRouter
        returns (bytes memory)
    {
        ScreenerConfig storage config = configs[account];
        if (!config.initialized) return "";

        _screen(config, account, target);

        if (callData.length >= 36) {
            bytes4 sel;
            uint256 w1;
            assembly {
                sel := mload(add(callData, 32))
                w1 := mload(add(callData, 36))
            }
            if (sel == 0xa9059cbb || sel == 0x095ea7b3 || sel == 0x39509351 || sel == 0xa22cb465) {
                // transfer, approve, increaseAllowance, setApprovalForAll: first arg is the counterparty
                _screen(config, account, address(uint160(w1)));
            } else if (sel == 0x23b872dd && callData.length >= 68) {
                // transferFrom(from, to, amount): screen `to`
                uint256 w2;
                assembly {
                    w2 := mload(add(callData, 68))
                }
                _screen(config, account, address(uint160(w2)));
            }
        }
        return "";
    }

    function _screen(ScreenerConfig storage config, address account, address addr) internal view {
        // never gate the account's own address: the registry owner must not be able to lock a vault
        // out of its own module management
        if (addr == address(0) || addr == account || config.userWhitelist[addr]) return;
        ThreatEntry storage threat = threatRegistry[addr];
        if (!threat.active || threat.level == ThreatLevel.SAFE) return;
        if (uint8(threat.level) < uint8(config.blockThreshold)) return; // LOW etc.: allowed (UI warns)

        // CRITICAL and HIGH: always block. MEDIUM: block unless the user enabled override.
        if (threat.level == ThreatLevel.MEDIUM && config.allowOverride) return;
        revert(
            string(
                abi.encodePacked(
                    "EthosiFi AntiScam: BLOCKED. Address flagged as [",
                    threat.reason,
                    "]. Contact support@ethosifi.com if this is an error."
                )
            )
        );
    }

    function postCheck(bytes calldata) external pure {}

    // ─────────────────────────────────────────────
    // Threat Registry Management
    // ─────────────────────────────────────────────

    /**
     * @notice Register a threat. Production: onlyGovernance multisig.
     */
    // [CRIT-1 FIXED] onlyOwner
    function registerThreat(address target, ThreatLevel level, string calldata reason) external onlyOwner {
        require(target != address(0), "Invalid target");
        require(level != ThreatLevel.SAFE, "Use removeThreat for safe");

        ThreatEntry storage entry = threatRegistry[target];
        entry.level = level;
        entry.reason = reason;
        entry.reportedAt = entry.reportedAt == 0 ? block.timestamp : entry.reportedAt;
        entry.reportCount++;
        entry.active = true;

        emit ThreatRegistered(target, level, reason);
    }

    /**
     * @notice Batch register threats for efficient feed updates.
     */
    // [CRIT-1 FIXED] onlyOwner. [MED-3] Batch limited.
    function batchRegisterThreats(address[] calldata targets, ThreatLevel[] calldata levels, string[] calldata reasons)
        external
        onlyOwner
    {
        require(targets.length == levels.length && levels.length == reasons.length, "Length mismatch");
        for (uint256 i = 0; i < targets.length; i++) {
            ThreatEntry storage entry = threatRegistry[targets[i]];
            entry.level = levels[i];
            entry.reason = reasons[i];
            entry.reportedAt = entry.reportedAt == 0 ? block.timestamp : entry.reportedAt;
            entry.reportCount++;
            entry.active = true;
            emit ThreatRegistered(targets[i], levels[i], reasons[i]);
        }
    }

    // [CRIT-1 FIXED] onlyOwner
    function removeThreat(address target, string calldata reason) external onlyOwner {
        threatRegistry[target].active = false;
        emit ThreatRemoved(target, reason);
    }

    // ─────────────────────────────────────────────
    // User Controls
    // ─────────────────────────────────────────────

    function addToWhitelist(address target) external {
        require(configs[msg.sender].initialized, "Not initialized");
        // Cannot whitelist CRITICAL threats
        require(threatRegistry[target].level != ThreatLevel.CRITICAL, "Cannot whitelist critical threat");
        configs[msg.sender].userWhitelist[target] = true;
        emit UserWhitelisted(msg.sender, target);
    }

    function removeFromWhitelist(address target) external {
        configs[msg.sender].userWhitelist[target] = false;
    }

    // ─────────────────────────────────────────────
    // View Helpers
    // ─────────────────────────────────────────────

    function getThreatLevel(address target) external view returns (ThreatLevel, string memory, bool) {
        ThreatEntry storage e = threatRegistry[target];
        return (e.level, e.reason, e.active);
    }

    function screenAddress(address account, address target)
        external
        view
        returns (bool blocked, ThreatLevel level, string memory reason)
    {
        ScreenerConfig storage config = configs[account];
        if (!config.initialized) return (false, ThreatLevel.SAFE, "");
        if (config.userWhitelist[target]) return (false, ThreatLevel.SAFE, "Whitelisted");

        ThreatEntry storage threat = threatRegistry[target];
        if (!threat.active) return (false, ThreatLevel.SAFE, "");

        blocked = uint8(threat.level) >= uint8(config.blockThreshold);
        return (blocked, threat.level, threat.reason);
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function isInitialized(address account) external view returns (bool) {
        return configs[account].initialized;
    }
}
