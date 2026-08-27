// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {IModule} from "erc7579/interfaces/IModule.sol";
import {ReentrancyGuard} from "solady/utils/ReentrancyGuard.sol";

/**
 * @title  PlainEnglishExecutor
 * @notice EthosiFi Vault — translates every transaction into human language before signing.
 *
 * @dev    SECURITY FIXES (2026-08 audit):
 *         [CRIT-1] labelContract() and batchLabelContracts() were callable by ANY address.
 *                  An attacker could label their own malicious contract as "Uniswap V3 Router"
 *                  or "USDC Token", causing the plain English summary to describe a safe
 *                  operation when the actual transaction drains the user's wallet.
 *                  Fixed: only the contract owner (EthosiFi governance) can label contracts.
 *         [MED-1]  batchLabelContracts() had no upper bound — DoS vector. Capped at 200.
 *         [MED-2]  Two-step ownership added.
 *         [MED-3]  ReentrancyGuard applied.
 */
contract PlainEnglishExecutor is IModule, ReentrancyGuard {

    uint256 private constant MODULE_TYPE_HOOK = 4;
    uint256 public  constant CONFIRMATION_EXPIRY   = 10 minutes;
    uint256 public  constant BATCH_LABEL_LIMIT     = 200;

    // ─── Access control ───────────────────────────────────────────────────────

    address public owner;
    address public pendingOwner;

    // ─── Known function selectors ─────────────────────────────────────────────

    bytes4 private constant ERC20_TRANSFER      = bytes4(keccak256("transfer(address,uint256)"));
    bytes4 private constant ERC20_APPROVE       = bytes4(keccak256("approve(address,uint256)"));
    bytes4 private constant ERC20_TRANSFER_FROM = bytes4(keccak256("transferFrom(address,address,uint256)"));
    bytes4 private constant WETH_DEPOSIT        = bytes4(keccak256("deposit()"));
    bytes4 private constant WETH_WITHDRAW       = bytes4(keccak256("withdraw(uint256)"));

    // ─── Types ────────────────────────────────────────────────────────────────

    enum RiskLevel { LOW, MEDIUM, HIGH, UNKNOWN }

    struct ExecutorConfig {
        bool initialized;
        bool requireConfirmation;
        bool warnOnUnknown;
        bool blockOnUnknown;
    }

    struct TransactionSummary {
        string    plainEnglish;
        bytes32   calldataHash;
        uint256   createdAt;
        bool      confirmed;
        uint256   confirmedAt;
        RiskLevel riskLevel;
    }

    // ─── Storage ──────────────────────────────────────────────────────────────

    mapping(address => ExecutorConfig)                                   public configs;
    mapping(address => mapping(bytes32 => TransactionSummary))           public summaries;

    /// @dev [CRIT-1] Only owner-approved labels. Attackers cannot self-label contracts.
    mapping(address => string)                                           public contractLabels;

    // ─── Events ───────────────────────────────────────────────────────────────

    event SummaryGenerated(address indexed account, bytes32 indexed summaryId, string plainEnglish, RiskLevel risk);
    event SummaryConfirmed(address indexed account, bytes32 indexed summaryId);
    event UnknownTransactionBlocked(address indexed account, address indexed target, bytes4 selector);
    event ContractLabeled(address indexed target, string label);
    event ContractLabelRemoved(address indexed target);
    event OwnershipTransferStarted(address indexed prev, address indexed next);
    event OwnershipTransferred(address indexed prev, address indexed next);

    // ─── Errors ───────────────────────────────────────────────────────────────

    error NotOwner();
    error AlreadyInitialized();
    error NotInitialized();
    error SummaryNotFound();
    error SummaryAlreadyConfirmed();
    error SummaryExpired();
    error BatchLimitExceeded();
    error ZeroAddress();

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // ─── ERC-7579 lifecycle ───────────────────────────────────────────────────

    function onInstall(bytes calldata data) external override {
        if (configs[msg.sender].initialized) revert AlreadyInitialized();
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

    // ─── Hook ─────────────────────────────────────────────────────────────────

    function preCheck(
        address account,
        address target,
        uint256 value,
        bytes calldata callData
    ) external nonReentrant returns (bytes memory) {
        ExecutorConfig storage config = configs[account];
        if (!config.initialized) return "";

        bytes32 calldataHash = keccak256(callData);

        if (config.requireConfirmation) {
            TransactionSummary storage existing = summaries[account][calldataHash];
            require(existing.confirmed,
                "EthosiFi: Read the plain English summary first. Call confirmSummary().");
            if (block.timestamp > existing.confirmedAt + CONFIRMATION_EXPIRY) {
                revert SummaryExpired();
            }
            require(existing.calldataHash == calldataHash,
                "EthosiFi: Transaction data changed after confirmation.");
        }

        if (callData.length >= 4) {
            bytes4 selector = bytes4(callData[:4]);
            (string memory description, RiskLevel risk) =
                _generateDescription(target, value, callData, selector);

            summaries[account][calldataHash] = TransactionSummary({
                plainEnglish: description,
                calldataHash: calldataHash,
                createdAt:    block.timestamp,
                confirmed:    !config.requireConfirmation,
                confirmedAt:  !config.requireConfirmation ? block.timestamp : 0,
                riskLevel:    risk
            });

            emit SummaryGenerated(account, calldataHash, description, risk);

            if (risk == RiskLevel.UNKNOWN && config.blockOnUnknown) {
                emit UnknownTransactionBlocked(account, target, selector);
                revert("EthosiFi: Unknown transaction type blocked. Proceed only if certain.");
            }
        } else if (value > 0) {
            summaries[account][calldataHash] = TransactionSummary({
                plainEnglish: string(abi.encodePacked(
                    "SEND ETH: You are sending ETH directly to ", _toHexString(target),
                    ". Amount: ", _uintToString(value), " wei. This cannot be undone."
                )),
                calldataHash: calldataHash,
                createdAt:    block.timestamp,
                confirmed:    true,
                confirmedAt:  block.timestamp,
                riskLevel:    RiskLevel.LOW
            });
        }

        return "";
    }

    function postCheck(bytes calldata) external pure {}

    // ─── User confirmation ────────────────────────────────────────────────────

    function confirmSummary(bytes32 calldataHash) external nonReentrant {
        if (!configs[msg.sender].initialized) revert NotInitialized();
        TransactionSummary storage summary = summaries[msg.sender][calldataHash];
        if (bytes(summary.plainEnglish).length == 0) revert SummaryNotFound();
        if (summary.confirmed) revert SummaryAlreadyConfirmed();

        summary.confirmed   = true;
        summary.confirmedAt = block.timestamp;

        emit SummaryConfirmed(msg.sender, calldataHash);
    }

    // ─── Contract label registry (owner only) ────────────────────────────────

    /**
     * @notice Add a verified label for a contract address.
     * @dev [CRIT-1] onlyOwner — prevents attackers labelling malicious contracts
     *      as trusted protocols to deceive users into signing drain transactions.
     */
    function labelContract(address target, string calldata label) external onlyOwner {
        if (target == address(0)) revert ZeroAddress();
        require(bytes(label).length > 0, "Empty label");
        contractLabels[target] = label;
        emit ContractLabeled(target, label);
    }

    /// @dev [MED-1] Capped at BATCH_LABEL_LIMIT to prevent DoS.
    function batchLabelContracts(
        address[] calldata targets,
        string[]  calldata labels
    ) external onlyOwner {
        if (targets.length > BATCH_LABEL_LIMIT) revert BatchLimitExceeded();
        require(targets.length == labels.length, "Length mismatch");
        for (uint256 i = 0; i < targets.length; i++) {
            if (targets[i] == address(0)) continue;
            contractLabels[targets[i]] = labels[i];
            emit ContractLabeled(targets[i], labels[i]);
        }
    }

    function removeLabel(address target) external onlyOwner {
        delete contractLabels[target];
        emit ContractLabelRemoved(target);
    }

    // ─── Two-step ownership ───────────────────────────────────────────────────

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotOwner();
        emit OwnershipTransferred(owner, pendingOwner);
        owner        = pendingOwner;
        pendingOwner = address(0);
    }

    // ─── Internal description generator ──────────────────────────────────────

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
                "SEND TOKEN: Transferring ", _uintToString(amount),
                " tokens to ", recipientLabel, ". This cannot be undone."
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
                    ? " UNLIMITED permission to spend ALL your tokens. They can drain your wallet at any time."
                    : string(abi.encodePacked(
                        " permission to spend up to ", _uintToString(amount), " tokens."))
            ));
            risk = unlimited ? RiskLevel.HIGH : RiskLevel.MEDIUM;

        } else if (selector == ERC20_TRANSFER_FROM) {
            (address from,, uint256 amount) = abi.decode(callData[4:], (address, address, uint256));
            description = string(abi.encodePacked(
                "TRANSFER FROM: ", targetLabel, " is moving ",
                _uintToString(amount), " tokens from ", _toHexString(from),
                ". Verify you authorised this."
            ));
            risk = RiskLevel.MEDIUM;

        } else if (selector == WETH_DEPOSIT) {
            description = string(abi.encodePacked(
                "WRAP ETH: Converting ", _uintToString(value), " wei into Wrapped ETH (WETH). Reversible."
            ));
            risk = RiskLevel.LOW;

        } else if (selector == WETH_WITHDRAW) {
            (uint256 amount) = abi.decode(callData[4:], (uint256));
            description = string(abi.encodePacked(
                "UNWRAP ETH: Converting ", _uintToString(amount), " WETH back to ETH. Reversible."
            ));
            risk = RiskLevel.LOW;

        } else {
            description = string(abi.encodePacked(
                "UNKNOWN OPERATION: Interacting with ", targetLabel,
                ". Function: ", _bytes4ToHex(selector),
                ". Not recognised by EthosiFi. Only proceed if you are certain of what this does."
            ));
            risk = RiskLevel.UNKNOWN;
        }
    }

    // ─── String utilities ─────────────────────────────────────────────────────

    function _toHexString(address addr) internal pure returns (string memory) {
        bytes memory buffer = new bytes(42);
        buffer[0] = '0'; buffer[1] = 'x';
        bytes16 hex16 = "0123456789abcdef";
        for (uint256 i = 0; i < 20; i++) {
            buffer[2 + i * 2] = hex16[uint8(bytes20(addr)[i]) >> 4];
            buffer[3 + i * 2] = hex16[uint8(bytes20(addr)[i]) & 0xf];
        }
        return string(buffer);
    }

    function _bytes4ToHex(bytes4 b) internal pure returns (string memory) {
        bytes memory buffer = new bytes(10);
        buffer[0] = '0'; buffer[1] = 'x';
        bytes16 hex16 = "0123456789abcdef";
        for (uint256 i = 0; i < 4; i++) {
            buffer[2 + i * 2] = hex16[uint8(b[i]) >> 4];
            buffer[3 + i * 2] = hex16[uint8(b[i]) & 0xf];
        }
        return string(buffer);
    }

    function _uintToString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value; uint256 digits;
        while (temp != 0) { digits++; temp /= 10; }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits--;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    // ─── ERC-7579 introspection ───────────────────────────────────────────────

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function isInitialized(address account) external view override returns (bool) {
        return configs[account].initialized;
    }
}
