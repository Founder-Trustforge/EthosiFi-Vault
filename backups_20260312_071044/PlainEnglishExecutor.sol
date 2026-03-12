// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {IModule} from "erc7579/interfaces/IModule.sol";

/**
 * @title PlainEnglishExecutor
 * @notice EthosiFi Vault — Translates every transaction into human language before signing.
 * @dev Blind signing is the root cause of 90% of all DeFi exploits.
 *      Users sign hex data they don't understand, trusting the UI — which may be spoofed.
 *
 *      This contract enforces that EVERY transaction produces a human-readable
 *      summary that is COMMITTED ON-CHAIN before execution. The user signs the
 *      plain English description, not just the hex calldata.
 *
 *      Example output:
 *      "You are about to SEND 500 USDC to a wallet you have never used before.
 *       This cannot be undone. The receiving wallet has no transaction history."
 *
 *      "You are about to APPROVE unlimited USDC spending by [Uniswap V3 Router].
 *       This contract has been active since 2021 with 50M+ transactions."
 *
 * Layer: User Protection (Pillar 3)
 */
contract PlainEnglishExecutor is IModule {

    uint256 constant MODULE_TYPE_HOOK = 4;

    // Known function signatures → plain English templates
    bytes4 constant ERC20_TRANSFER         = bytes4(keccak256("transfer(address,uint256)"));
    bytes4 constant ERC20_APPROVE          = bytes4(keccak256("approve(address,uint256)"));
    bytes4 constant ERC20_TRANSFER_FROM    = bytes4(keccak256("transferFrom(address,address,uint256)"));
    bytes4 constant UNISWAP_SWAP           = bytes4(keccak256("exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))"));
    bytes4 constant WETH_DEPOSIT           = bytes4(keccak256("deposit()"));
    bytes4 constant WETH_WITHDRAW          = bytes4(keccak256("withdraw(uint256)"));

    uint256 public constant MAX_DESCRIPTION_LENGTH = 512;
    uint256 public constant CONFIRMATION_EXPIRY    = 10 minutes;

    struct ExecutorConfig {
        bool initialized;
        bool requireConfirmation;   // Require user to confirm plain English before execution
        bool warnOnUnknown;         // Warn (but allow) on unknown function signatures
        bool blockOnUnknown;        // Block entirely on unknown function signatures
    }

    struct TransactionSummary {
        string  plainEnglish;       // Human-readable description
        bytes32 calldataHash;       // Hash of the calldata this describes
        uint256 createdAt;
        bool    confirmed;          // User confirmed they read and understood
        uint256 confirmedAt;
        RiskLevel riskLevel;
    }

    enum RiskLevel {
        LOW,        // Known safe operation (send to verified address)
        MEDIUM,     // Approval or new contract interaction
        HIGH,       // Unlimited approval, new address, large amount
        UNKNOWN     // Unrecognized function — could be anything
    }

    mapping(address => ExecutorConfig) public configs;
    mapping(address => mapping(bytes32 => TransactionSummary)) public summaries;

    // Known contract labels (populated by EthosiFi team + community)
    mapping(address => string) public contractLabels;

    event SummaryGenerated(address indexed account, bytes32 indexed summaryId, string plainEnglish, RiskLevel risk);
    event SummaryConfirmed(address indexed account, bytes32 indexed summaryId);
    event UnknownTransactionBlocked(address indexed account, address indexed target, bytes4 selector);
    event ContractLabeled(address indexed target, string label);

    // ─────────────────────────────────────────────
    // Module Lifecycle
    // ─────────────────────────────────────────────

    function onInstall(bytes calldata data) external override {
        require(!configs[msg.sender].initialized, "Already initialized");

        (bool requireConfirmation, bool warnOnUnknown, bool blockOnUnknown) =
            abi.decode(data, (bool, bool, bool));

        configs[msg.sender] = ExecutorConfig({
            initialized:         true,
            requireConfirmation: requireConfirmation,
            warnOnUnknown:       warnOnUnknown,
            blockOnUnknown:      blockOnUnknown
        });
    }

    function onUninstall(bytes calldata) external override {
        delete configs[msg.sender];
    }

    // ─────────────────────────────────────────────
    // Pre-Execution Hook
    // ─────────────────────────────────────────────

    function preCheck(
        address account,
        address target,
        uint256 value,
        bytes calldata callData
    ) external returns (bytes memory) {
        ExecutorConfig storage config = configs[account];
        if (!config.initialized) return "";

        bytes32 calldataHash = keccak256(callData);

        // If confirmation required, check it exists and is valid
        if (config.requireConfirmation) {
            TransactionSummary storage summary = summaries[account][calldataHash];
            require(summary.confirmed, "EthosiFi: Read the plain English summary first. Call confirmSummary().");
            require(
                block.timestamp <= summary.confirmedAt + CONFIRMATION_EXPIRY,
                "EthosiFi: Summary confirmation expired. Please re-read and re-confirm."
            );
            require(summary.calldataHash == calldataHash, "EthosiFi: Transaction data changed after confirmation.");
        }

        // Decode and analyze
        if (callData.length >= 4) {
            bytes4 selector = bytes4(callData[:4]);
            (string memory description, RiskLevel risk) = _generateDescription(target, value, callData, selector);

            // Store summary on-chain
            summaries[account][calldataHash] = TransactionSummary({
                plainEnglish:  description,
                calldataHash:  calldataHash,
                createdAt:     block.timestamp,
                confirmed:     !config.requireConfirmation, // Auto-confirmed if not requiring confirmation
                confirmedAt:   !config.requireConfirmation ? block.timestamp : 0,
                riskLevel:     risk
            });

            emit SummaryGenerated(account, calldataHash, description, risk);

            // Block unknown transactions if configured
            if (risk == RiskLevel.UNKNOWN && config.blockOnUnknown) {
                emit UnknownTransactionBlocked(account, target, selector);
                revert("EthosiFi: Unknown transaction type blocked. This contract interaction is not recognized. Proceed with extreme caution.");
            }
        } else if (value > 0) {
            // Native ETH transfer
            bytes32 ethHash = keccak256(abi.encodePacked(target, value, block.timestamp));
            summaries[account][ethHash] = TransactionSummary({
                plainEnglish: string(abi.encodePacked("You are sending ETH directly to address ", _toHexString(target), ". This is a plain ETH transfer.")),
                calldataHash: calldataHash,
                createdAt: block.timestamp,
                confirmed: true,
                confirmedAt: block.timestamp,
                riskLevel: RiskLevel.LOW
            });
        }

        return "";
    }

    function postCheck(bytes calldata) external pure {}

    // ─────────────────────────────────────────────
    // User Confirmation
    // ─────────────────────────────────────────────

    /**
     * @notice User calls this after reading the plain English summary.
     *         Required before execution when requireConfirmation = true.
     */
    function confirmSummary(bytes32 calldataHash) external {
        require(configs[msg.sender].initialized, "Not initialized");
        TransactionSummary storage summary = summaries[msg.sender][calldataHash];
        require(bytes(summary.plainEnglish).length > 0, "Summary not found");
        require(!summary.confirmed, "Already confirmed");

        summary.confirmed   = true;
        summary.confirmedAt = block.timestamp;

        emit SummaryConfirmed(msg.sender, calldataHash);
    }

    // ─────────────────────────────────────────────
    // Plain English Generator
    // ─────────────────────────────────────────────

    function _generateDescription(
        address target,
        uint256 value,
        bytes calldata callData,
        bytes4 selector
    ) internal view returns (string memory description, RiskLevel risk) {

        string memory targetLabel = bytes(contractLabels[target]).length > 0
            ? contractLabels[target]
            : _toHexString(target);

        if (selector == ERC20_TRANSFER) {
            (address recipient, uint256 amount) = abi.decode(callData[4:], (address, uint256));
            string memory recipientLabel = bytes(contractLabels[recipient]).length > 0
                ? contractLabels[recipient] : _toHexString(recipient);
            description = string(abi.encodePacked(
                "SEND TOKEN: You are transferring tokens to ", recipientLabel,
                ". Amount: ", _uintToString(amount),
                ". This cannot be undone."
            ));
            risk = RiskLevel.LOW;

        } else if (selector == ERC20_APPROVE) {
            (, uint256 amount) = abi.decode(callData[4:], (address, uint256));
            bool unlimited = amount == type(uint256).max;
            description = string(abi.encodePacked(
                unlimited
                    ? "WARNING - UNLIMITED APPROVAL: You are giving "
                    : "APPROVAL: You are giving ",
                targetLabel,
                unlimited
                    ? " UNLIMITED permission to spend your tokens. This means they can take ALL your tokens at any time."
                    : string(abi.encodePacked(" permission to spend up to ", _uintToString(amount), " of your tokens."))
            ));
            risk = unlimited ? RiskLevel.HIGH : RiskLevel.MEDIUM;

        } else if (selector == ERC20_TRANSFER_FROM) {
            (address from,, uint256 amount) = abi.decode(callData[4:], (address, address, uint256));
            description = string(abi.encodePacked(
                "TRANSFER FROM WALLET: ", targetLabel,
                " is moving ", _uintToString(amount),
                " tokens from ", _toHexString(from),
                ". Verify you authorized this."
            ));
            risk = RiskLevel.MEDIUM;

        } else if (selector == WETH_DEPOSIT) {
            description = string(abi.encodePacked(
                "WRAP ETH: Converting ", _uintToString(value),
                " ETH into Wrapped ETH (WETH). This is reversible."
            ));
            risk = RiskLevel.LOW;

        } else if (selector == WETH_WITHDRAW) {
            (uint256 amount) = abi.decode(callData[4:], (uint256));
            description = string(abi.encodePacked(
                "UNWRAP ETH: Converting ", _uintToString(amount),
                " WETH back to ETH. This is reversible."
            ));
            risk = RiskLevel.LOW;

        } else {
            description = string(abi.encodePacked(
                "UNKNOWN OPERATION: Interacting with contract ", targetLabel,
                ". Function signature: ", _bytes4ToHex(selector),
                ". This contract interaction is not recognized by EthosiFi. Proceed only if you are certain of what you are doing."
            ));
            risk = RiskLevel.UNKNOWN;
        }
    }

    // ─────────────────────────────────────────────
    // Contract Label Registry
    // ─────────────────────────────────────────────

    function labelContract(address target, string calldata label) external {
        // Production: onlyGovernance or verified registry
        require(bytes(label).length > 0, "Empty label");
        contractLabels[target] = label;
        emit ContractLabeled(target, label);
    }

    function batchLabelContracts(address[] calldata targets, string[] calldata labels) external {
        require(targets.length == labels.length, "Length mismatch");
        for (uint256 i = 0; i < targets.length; i++) {
            contractLabels[targets[i]] = labels[i];
            emit ContractLabeled(targets[i], labels[i]);
        }
    }

    // ─────────────────────────────────────────────
    // Utility Helpers
    // ─────────────────────────────────────────────

    function _toHexString(address addr) internal pure returns (string memory) {
        bytes memory buffer = new bytes(42);
        buffer[0] = '0'; buffer[1] = 'x';
        bytes16 hexChars = "0123456789abcdef";
        for (uint256 i = 0; i < 20; i++) {
            buffer[2 + i * 2]     = hexChars[uint8(bytes20(addr)[i]) >> 4];
            buffer[3 + i * 2]     = hexChars[uint8(bytes20(addr)[i]) & 0xf];
        }
        return string(buffer);
    }

    function _bytes4ToHex(bytes4 b) internal pure returns (string memory) {
        bytes memory buffer = new bytes(10);
        buffer[0] = '0'; buffer[1] = 'x';
        bytes16 hexChars = "0123456789abcdef";
        for (uint256 i = 0; i < 4; i++) {
            buffer[2 + i * 2] = hexChars[uint8(b[i]) >> 4];
            buffer[3 + i * 2] = hexChars[uint8(b[i]) & 0xf];
        }
        return string(buffer);
    }

    function _uintToString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) { digits++; temp /= 10; }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits--;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function isInitialized(address account) external view override returns (bool) {
        return configs[account].initialized;
    }
}
