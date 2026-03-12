// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {IModule} from "erc7579/interfaces/IModule.sol";

/**
 * @title AIThreatOracle
 * @notice EthosiFi Vault — Real-time AI risk scoring for every transaction.
 * @dev Every transaction receives a risk score 0–100 before execution.
 *      Score factors:
 *        - Recipient wallet age and transaction history
 *        - Contract deployment age and audit status
 *        - Token volatility and rug-pull indicators
 *        - Behavioral anomalies (unusual time, amount, frequency)
 *        - Known attack pattern matching
 *        - Cross-chain threat intelligence correlation
 *
 *      Score thresholds (configurable per user):
 *        0–30:  GREEN  — Execute normally
 *        31–60: YELLOW — Warn user, add confirmation step
 *        61–85: ORANGE — Require guardian notification
 *        86–100: RED   — Block transaction automatically
 *
 *      AI scores are submitted by EthosiFi's off-chain AI engine
 *      and committed on-chain via a trusted oracle network.
 *      Chainlink Functions or a dedicated EthosiFi oracle node
 *      submits signed scores before transaction execution.
 *
 * Layer: User Protection (Pillar 4)
 */
contract AIThreatOracle is IModule {

    uint256 constant MODULE_TYPE_HOOK = 4;

    uint8 public constant SCORE_GREEN  = 30;
    uint8 public constant SCORE_YELLOW = 60;
    uint8 public constant SCORE_ORANGE = 85;
    uint8 public constant SCORE_RED    = 86;  // Block threshold

    enum RiskColor { GREEN, YELLOW, ORANGE, RED }

    struct OracleConfig {
        bool  initialized;
        uint8 blockThreshold;       // Default: 86 (RED)
        uint8 guardianAlertThreshold; // Default: 61 (ORANGE)
        bool  requireScoreForAll;   // Require AI score for all transactions
        address trustedOracle;      // EthosiFi oracle address
    }

    struct ThreatScore {
        uint8   score;              // 0–100
        string  reasoning;          // AI plain-English explanation
        uint256 scoredAt;           // Timestamp
        bytes32 txHash;             // Transaction being scored
        bool    valid;
        RiskColor color;
    }

    struct BehaviorProfile {
        uint256 avgTransactionAmount;
        uint256 totalTransactions;
        uint256 lastTransactionAt;
        uint256 unusualTimeCount;    // Transactions at unusual hours
        uint256 newAddressCount;     // Transactions to new addresses
        uint256 highRiskCount;       // Previous high-risk transactions attempted
    }

    mapping(address => OracleConfig) public configs;
    mapping(address => mapping(bytes32 => ThreatScore)) public scores;
    mapping(address => BehaviorProfile) public profiles;

    // Global AI-flagged addresses with scores
    mapping(address => uint8) public globalRiskScores;

    // Oracle signer registry
    mapping(address => bool) public trustedOracles;

    // Statistics
    uint256 public totalScored;
    uint256 public totalBlocked;
    uint256 public totalAlerted;

    event TransactionScored(address indexed account, bytes32 indexed txHash, uint8 score, RiskColor color, string reasoning);
    event TransactionBlockedByAI(address indexed account, bytes32 indexed txHash, uint8 score, string reasoning);
    event GuardianAlertTriggered(address indexed account, bytes32 indexed txHash, uint8 score);
    event BehaviorAnomalyDetected(address indexed account, string anomalyType);
    event OracleScoreSubmitted(address indexed oracle, bytes32 indexed txHash, uint8 score);

    // ─────────────────────────────────────────────
    // Module Lifecycle
    // ─────────────────────────────────────────────

    function onInstall(bytes calldata data) external override {
        require(!configs[msg.sender].initialized, "Already initialized");

        (uint8 blockThreshold, uint8 alertThreshold, bool requireScoreForAll, address oracle) =
            abi.decode(data, (uint8, uint8, bool, address));

        configs[msg.sender] = OracleConfig({
            initialized:             true,
            blockThreshold:          blockThreshold > 0 ? blockThreshold : SCORE_RED,
            guardianAlertThreshold:  alertThreshold > 0 ? alertThreshold : SCORE_ORANGE + 1,
            requireScoreForAll:      requireScoreForAll,
            trustedOracle:           oracle
        });
    }

    function onUninstall(bytes calldata) external override {
        delete configs[msg.sender];
    }

    // ─────────────────────────────────────────────
    // Hook: Check AI Score Before Every Transaction
    // ─────────────────────────────────────────────

    function preCheck(
        address account,
        address target,
        uint256 value,
        bytes calldata callData
    ) external returns (bytes memory) {
        OracleConfig storage config = configs[account];
        if (!config.initialized) return "";

        totalScored++;
        bytes32 txHash = keccak256(abi.encodePacked(account, target, value, callData, block.timestamp));

        // Check global risk score for target
        uint8 globalScore = globalRiskScores[target];

        // Check if we have a fresh oracle-submitted score
        ThreatScore storage existingScore = scores[account][txHash];

        uint8 finalScore;
        string memory reasoning;

        if (existingScore.valid && block.timestamp <= existingScore.scoredAt + 5 minutes) {
            // Use oracle-submitted score
            finalScore = existingScore.score;
            reasoning  = existingScore.reasoning;
        } else if (globalScore > 0) {
            // Use global AI score for this address
            finalScore = globalScore;
            reasoning  = "Global AI threat intelligence score.";
        } else {
            // Fallback: behavioral heuristics
            (finalScore, reasoning) = _heuristicScore(account, target, value, callData);
        }

        // Update behavior profile
        _updateProfile(account, target, value, finalScore);

        RiskColor color = _getColor(finalScore);

        // Store score
        scores[account][txHash] = ThreatScore({
            score:     finalScore,
            reasoning: reasoning,
            scoredAt:  block.timestamp,
            txHash:    txHash,
            valid:     true,
            color:     color
        });

        emit TransactionScored(account, txHash, finalScore, color, reasoning);

        // Block if above threshold
        if (finalScore >= config.blockThreshold) {
            totalBlocked++;
            emit TransactionBlockedByAI(account, txHash, finalScore, reasoning);
            revert(string(abi.encodePacked(
                "EthosiFi AI: Transaction blocked. Risk score: ",
                _uintToString(finalScore),
                "/100. Reason: ", reasoning
            )));
        }

        // Alert guardians if above alert threshold
        if (finalScore >= config.guardianAlertThreshold) {
            totalAlerted++;
            emit GuardianAlertTriggered(account, txHash, finalScore);
        }

        return "";
    }

    function postCheck(bytes calldata) external pure {}

    // ─────────────────────────────────────────────
    // Oracle Score Submission
    // ─────────────────────────────────────────────

    /**
     * @notice EthosiFi AI oracle submits a score for a pending transaction.
     * @dev Called by the EthosiFi oracle node before the user submits their UserOp.
     *      Score is valid for 5 minutes.
     */
    function submitScore(
        address account,
        bytes32 txHash,
        uint8 score,
        string calldata reasoning,
        bytes calldata signature
    ) external {
        require(trustedOracles[msg.sender] || msg.sender == configs[account].trustedOracle, "Not trusted oracle");
        require(score <= 100, "Invalid score");

        // Verify oracle signature
        bytes32 messageHash = keccak256(abi.encodePacked(account, txHash, score, reasoning));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        require(_recoverSigner(ethHash, signature) == msg.sender, "Invalid signature");

        RiskColor color = _getColor(score);

        scores[account][txHash] = ThreatScore({
            score:     score,
            reasoning: reasoning,
            scoredAt:  block.timestamp,
            txHash:    txHash,
            valid:     true,
            color:     color
        });

        emit OracleScoreSubmitted(msg.sender, txHash, score);
    }

    /**
     * @notice Update global risk score for an address. Fed by AI threat feeds.
     */
    function updateGlobalScore(address target, uint8 score) external {
        require(trustedOracles[msg.sender], "Not trusted oracle");
        globalRiskScores[target] = score;
    }

    function addTrustedOracle(address oracle) external {
        // Production: onlyGovernance
        trustedOracles[oracle] = true;
    }

    // ─────────────────────────────────────────────
    // Behavioral Heuristics (Fallback Scoring)
    // ─────────────────────────────────────────────

    function _heuristicScore(
        address account,
        address target,
        uint256 value,
        bytes calldata callData
    ) internal view returns (uint8 score, string memory reasoning) {
        BehaviorProfile storage profile = profiles[account];

        score = 10; // Base score
        reasoning = "Heuristic analysis: ";

        // New address penalty
        if (globalRiskScores[target] == 0 && target.code.length == 0) {
            score += 15;
            reasoning = string(abi.encodePacked(reasoning, "First interaction with this address. "));
        }

        // Unusual amount (>3x average)
        if (profile.avgTransactionAmount > 0 && value > profile.avgTransactionAmount * 3) {
            score += 25;
            reasoning = string(abi.encodePacked(reasoning, "Amount is unusually large vs your history. "));
        }

        // Unusual time (simplified: block timestamp modulo day)
        uint256 hourOfDay = (block.timestamp % 86400) / 3600;
        if (hourOfDay >= 1 && hourOfDay <= 5) {
            score += 10;
            reasoning = string(abi.encodePacked(reasoning, "Transaction at unusual hour. "));
        }

        // Approve with max uint (unlimited approval)
        if (callData.length >= 68) {
            bytes4 selector = bytes4(callData[:4]);
            if (selector == bytes4(keccak256("approve(address,uint256)"))) {
                uint256 amount = uint256(bytes32(callData[36:68]));
                if (amount == type(uint256).max) {
                    score += 30;
                    reasoning = string(abi.encodePacked(reasoning, "UNLIMITED token approval detected. "));
                }
            }
        }

        // High risk history
        if (profile.highRiskCount > 2) {
            score += 10;
            reasoning = string(abi.encodePacked(reasoning, "Multiple previous high-risk attempts detected. "));
        }

        if (score > 100) score = 100;
    }

    function _updateProfile(address account, address target, uint256 value, uint8 riskScore) internal {
        BehaviorProfile storage profile = profiles[account];

        // Rolling average
        if (profile.totalTransactions == 0) {
            profile.avgTransactionAmount = value;
        } else {
            profile.avgTransactionAmount = (profile.avgTransactionAmount * profile.totalTransactions + value)
                / (profile.totalTransactions + 1);
        }

        profile.totalTransactions++;
        profile.lastTransactionAt = block.timestamp;

        if (riskScore >= SCORE_RED) {
            profile.highRiskCount++;
        }

        // Unusual hours
        uint256 hourOfDay = (block.timestamp % 86400) / 3600;
        if (hourOfDay >= 1 && hourOfDay <= 5) {
            profile.unusualTimeCount++;
            if (profile.unusualTimeCount > 3) {
                emit BehaviorAnomalyDetected(account, "Multiple unusual-hour transactions");
            }
        }
    }

    function _getColor(uint8 score) internal pure returns (RiskColor) {
        if (score <= SCORE_GREEN)  return RiskColor.GREEN;
        if (score <= SCORE_YELLOW) return RiskColor.YELLOW;
        if (score <= SCORE_ORANGE) return RiskColor.ORANGE;
        return RiskColor.RED;
    }

    function _recoverSigner(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(hash, v, r, s);
    }

    function _uintToString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value; uint256 digits;
        while (temp != 0) { digits++; temp /= 10; }
        bytes memory buffer = new bytes(digits);
        while (value != 0) { digits--; buffer[digits] = bytes1(uint8(48 + value % 10)); value /= 10; }
        return string(buffer);
    }

    // ─────────────────────────────────────────────
    // View Helpers
    // ─────────────────────────────────────────────

    function getScore(address account, bytes32 txHash) external view returns (
        uint8 score, RiskColor color, string memory reasoning, bool valid
    ) {
        ThreatScore storage s = scores[account][txHash];
        return (s.score, s.color, s.reasoning, s.valid);
    }

    function getBehaviorProfile(address account) external view returns (
        uint256 avgAmount, uint256 totalTx, uint256 lastTx, uint256 highRiskCount
    ) {
        BehaviorProfile storage p = profiles[account];
        return (p.avgTransactionAmount, p.totalTransactions, p.lastTransactionAt, p.highRiskCount);
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
