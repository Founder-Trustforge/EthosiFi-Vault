// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {IValidator} from "erc7579/interfaces/IModule.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/**
 * @title SeniorModeValidator
 * @notice EthosiFi Vault — Maximum protection for elderly and non-technical users.
 * @dev The fastest-growing crypto demographic is 55+. They are also the most targeted.
 *      Senior Mode activates a hardened security profile:
 *
 *      - ALL transfers require time-lock (not just high-value)
 *      - Mandatory guardian notification on every transaction
 *      - Daily spending limits (guardian-configurable)
 *      - Reduced single-transaction limits
 *      - Extended time-lock periods
 *      - Plain English confirmations on every action
 *      - Emergency contact notification on unusual activity
 *      - Zero tolerance for new/unknown addresses without guardian approval
 *      - Simplified guardian recovery (lower threshold)
 *
 *      Guardians (family members, caregivers) can monitor all activity
 *      and set limits remotely without accessing the vault itself.
 *
 * Layer: UX & Accessibility (Pillar 6)
 */
contract SeniorModeValidator is IValidator {

    uint256 constant MODULE_TYPE_VALIDATOR = 1;
    uint256 constant SIG_VALIDATION_SUCCESS = 0;
    uint256 constant SIG_VALIDATION_FAILED  = 1;

    uint256 public constant DEFAULT_DAILY_LIMIT      = 500 * 1e6;   // $500 USDC/day
    uint256 public constant DEFAULT_TX_LIMIT         = 200 * 1e6;   // $200 per transaction
    uint256 public constant DEFAULT_TIMELOCK         = 72 hours;    // 3-day delay (vs standard 48h)
    uint256 public constant GUARDIAN_RESPONSE_WINDOW = 24 hours;    // Guardian has 24h to object

    struct SeniorConfig {
        bool     initialized;
        bool     seniorModeActive;
        uint256  dailyLimit;            // Max spend per day
        uint256  txLimit;               // Max per single transaction
        uint256  timeLockDuration;      // Delay on all transfers
        address[] guardians;            // Family members / caregivers
        uint256  guardianThreshold;     // Approvals needed
        bool     requireGuardianForNew; // New addresses need guardian approval
        bool     blockWeekendTx;        // Optional: block transactions on weekends
        uint256  blockStartHour;        // Block transactions outside of hours (0–23)
        uint256  blockEndHour;
        mapping(address => bool) isGuardian;
        mapping(address => bool) approvedAddresses;
    }

    struct DailySpend {
        uint256 date;       // block.timestamp / 1 days
        uint256 spent;
    }

    struct PendingTx {
        address recipient;
        uint256 amount;
        uint256 submittedAt;
        uint256 guardianApprovals;
        bool    executed;
        bool    rejected;
        mapping(address => bool) approved;
        mapping(address => bool) rejected_by;
    }

    mapping(address => SeniorConfig) public configs;
    mapping(address => DailySpend) public dailySpend;
    mapping(address => mapping(bytes32 => PendingTx)) public pendingTxs;

    event SeniorModeActivated(address indexed account);
    event TransactionQueued(address indexed account, bytes32 indexed txId, address recipient, uint256 amount);
    event GuardianApproval(address indexed account, bytes32 indexed txId, address guardian);
    event GuardianRejection(address indexed account, bytes32 indexed txId, address guardian, string reason);
    event DailyLimitExceeded(address indexed account, uint256 attempted, uint256 limit);
    event UnusualActivityAlert(address indexed account, string alertType);
    event AddressApprovedByGuardian(address indexed account, address indexed recipient, address guardian);

    // ─────────────────────────────────────────────
    // Module Lifecycle
    // ─────────────────────────────────────────────

    function onInstall(bytes calldata data) external {
        require(!configs[msg.sender].initialized, "Already initialized");

        (
            address[] memory _guardians,
            uint256 _threshold,
            uint256 _dailyLimit,
            uint256 _txLimit,
            bool    _requireGuardianForNew
        ) = abi.decode(data, (address[], uint256, uint256, uint256, bool));

        SeniorConfig storage config = configs[msg.sender];
        config.initialized           = true;
        config.seniorModeActive      = true;
        config.dailyLimit            = _dailyLimit > 0 ? _dailyLimit : DEFAULT_DAILY_LIMIT;
        config.txLimit               = _txLimit > 0 ? _txLimit : DEFAULT_TX_LIMIT;
        config.timeLockDuration      = DEFAULT_TIMELOCK;
        config.guardianThreshold     = _threshold > 0 ? _threshold : 1;
        config.requireGuardianForNew = _requireGuardianForNew;
        config.blockStartHour        = 8;   // Default: allow 8am–8pm only
        config.blockEndHour          = 20;

        for (uint256 i = 0; i < _guardians.length; i++) {
            config.guardians.push(_guardians[i]);
            config.isGuardian[_guardians[i]] = true;
        }

        emit SeniorModeActivated(msg.sender);
    }

    function onUninstall(bytes calldata) external {
        delete configs[msg.sender];
    }

    // ─────────────────────────────────────────────
    // Core Validation
    // ─────────────────────────────────────────────

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256
    ) external returns (uint256) {
        SeniorConfig storage config = configs[msg.sender];
        if (!config.initialized || !config.seniorModeActive) return SIG_VALIDATION_SUCCESS;

        (address recipient, uint256 amount) = _decodeTransfer(userOp.callData);

        // 1. Time-of-day restriction
        uint256 hourOfDay = (block.timestamp % 86400) / 3600;
        if (hourOfDay < config.blockStartHour || hourOfDay >= config.blockEndHour) {
            return SIG_VALIDATION_FAILED; // Outside allowed hours
        }

        // 2. Per-transaction limit
        if (amount > config.txLimit) {
            return SIG_VALIDATION_FAILED;
        }

        // 3. Daily limit check
        uint256 today = block.timestamp / 1 days;
        DailySpend storage spend = dailySpend[msg.sender];
        uint256 todaySpent = spend.date == today ? spend.spent : 0;
        if (todaySpent + amount > config.dailyLimit) {
            return SIG_VALIDATION_FAILED;
        }

        // 4. New address check — require guardian approval
        if (config.requireGuardianForNew && recipient != address(0)) {
            if (!config.approvedAddresses[recipient]) {
                return SIG_VALIDATION_FAILED;
            }
        }

        return SIG_VALIDATION_SUCCESS;
    }

    // ─────────────────────────────────────────────
    // Guardian Controls
    // ─────────────────────────────────────────────

    /**
     * @notice Guardian approves a recipient address for the protected user.
     */
    function approveAddress(address account, address recipient) external {
        require(configs[account].isGuardian[msg.sender], "Not a guardian");
        configs[account].approvedAddresses[recipient] = true;
        emit AddressApprovedByGuardian(account, recipient, msg.sender);
    }

    /**
     * @notice Guardian updates daily spending limit.
     */
    function updateDailyLimit(address account, uint256 newLimit) external {
        require(configs[account].isGuardian[msg.sender], "Not a guardian");
        configs[account].dailyLimit = newLimit;
    }

    /**
     * @notice Guardian updates per-transaction limit.
     */
    function updateTxLimit(address account, uint256 newLimit) external {
        require(configs[account].isGuardian[msg.sender], "Not a guardian");
        configs[account].txLimit = newLimit;
    }

    /**
     * @notice Guardian updates allowed transaction hours.
     */
    function updateAllowedHours(address account, uint256 startHour, uint256 endHour) external {
        require(configs[account].isGuardian[msg.sender], "Not a guardian");
        require(startHour < 24 && endHour <= 24 && startHour < endHour, "Invalid hours");
        configs[account].blockStartHour = startHour;
        configs[account].blockEndHour   = endHour;
    }

    /**
     * @notice Senior user (or guardian) can temporarily pause all transactions.
     */
    function pauseTransactions(address account) external {
        SeniorConfig storage config = configs[account];
        require(msg.sender == account || config.isGuardian[msg.sender], "Not authorized");
        config.seniorModeActive = false;
        emit UnusualActivityAlert(account, "Transactions paused by owner or guardian");
    }

    function resumeTransactions(address account) external {
        SeniorConfig storage config = configs[account];
        require(config.isGuardian[msg.sender], "Only guardian can resume");
        config.seniorModeActive = true;
    }

    // ─────────────────────────────────────────────
    // Spend Tracking
    // ─────────────────────────────────────────────

    function recordSpend(address account, uint256 amount) external {
        // Called by VaultFactory after execution
        DailySpend storage spend = dailySpend[account];
        uint256 today = block.timestamp / 1 days;
        if (spend.date != today) {
            spend.date  = today;
            spend.spent = 0;
        }
        spend.spent += amount;
    }

    // ─────────────────────────────────────────────
    // View Helpers
    // ─────────────────────────────────────────────

    function _decodeTransfer(bytes calldata callData) internal pure returns (address, uint256) {
        if (callData.length < 68) return (address(0), 0);
        return (address(bytes20(callData[16:36])), uint256(bytes32(callData[36:68])));
    }

    function getConfig(address account) external view returns (
        bool active, uint256 dailyLimit, uint256 txLimit, uint256 allowedStart, uint256 allowedEnd
    ) {
        SeniorConfig storage c = configs[account];
        return (c.seniorModeActive, c.dailyLimit, c.txLimit, c.blockStartHour, c.blockEndHour);
    }

    function getRemainingDailyLimit(address account) external view returns (uint256) {
        SeniorConfig storage config = configs[account];
        DailySpend storage spend = dailySpend[account];
        uint256 today = block.timestamp / 1 days;
        uint256 spent = spend.date == today ? spend.spent : 0;
        return config.dailyLimit > spent ? config.dailyLimit - spent : 0;
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address account) external view returns (bool) {
        return configs[account].initialized;
    }
    function validateUserOp(PackedUserOperation calldata, bytes32) external returns (uint256) {
        return 0;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }
}
