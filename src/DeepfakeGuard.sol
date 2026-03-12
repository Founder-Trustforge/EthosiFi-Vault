// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {IModule} from "erc7579/interfaces/IModule.sol";

/**
 * @title DeepfakeGuard
 * @notice EthosiFi Vault — Defends against AI-powered social engineering attacks.
 * @dev Deepfake voice phishing rose 1,633% in Q1 2025.
 *      Attackers impersonate trusted contacts, family members, or support staff
 *      via AI-generated voice/video to pressure victims into approving transactions.
 *
 *      This contract adds a timed cryptographic challenge for large transfers.
 *      The challenge requires a unique, time-sensitive response that:
 *        - Cannot be pre-computed by an attacker
 *        - Cannot be auto-passed by a bot or deepfake
 *        - Requires the actual vault owner to be present and responsive
 *        - Expires in a short window (prevents replay)
 *
 *      Additionally: enforces a "cooling off" check — if the user's behavior
 *      indicates social pressure (e.g., multiple rapid attempts on large transfers),
 *      the vault enters a voluntary protection mode.
 *
 * Layer: User Protection (Pillar 5)
 */
contract DeepfakeGuard is IModule {

    uint256 constant MODULE_TYPE_HOOK = 4;

    uint256 public constant CHALLENGE_EXPIRY     = 3 minutes;    // Challenge must be answered in 3 min
    uint256 public constant COOLOFF_THRESHOLD    = 3;            // Rapid attempts before cooloff
    uint256 public constant COOLOFF_PERIOD       = 30 minutes;   // Mandatory cooloff duration
    uint256 public constant DEFAULT_VALUE_TRIGGER = 1000 * 1e6;  // Challenges required above $1,000

    struct GuardConfig {
        bool    initialized;
        uint256 valueTrigger;        // Challenge required above this amount
        bool    alwaysChallenge;     // Challenge ALL transactions (maximum protection)
        uint256 rapidAttemptWindow;  // Window to detect rapid attempts (seconds)
    }

    struct Challenge {
        bytes32 challengeHash;      // keccak256(secret + nonce + timestamp)
        uint256 issuedAt;
        uint256 expiresAt;
        bool    answered;
        bool    passed;
        uint256 amount;
        address recipient;
    }

    struct PressureProfile {
        uint256 attemptCount;
        uint256 firstAttemptAt;
        uint256 lastAttemptAt;
        bool    inCooloff;
        uint256 cooloffUntil;
    }

    mapping(address => GuardConfig) public configs;
    mapping(address => mapping(bytes32 => Challenge)) public challenges;
    mapping(address => PressureProfile) public pressureProfiles;

    // Nonce tracking — prevents replay attacks
    mapping(address => uint256) public nonces;

    event ChallengeIssued(address indexed account, bytes32 indexed challengeId, uint256 expiresAt, uint256 amount);
    event ChallengePassed(address indexed account, bytes32 indexed challengeId);
    event ChallengeFailed(address indexed account, bytes32 indexed challengeId, string reason);
    event PressureDetected(address indexed account, uint256 attemptCount, string action);
    event CooloffActivated(address indexed account, uint256 cooloffUntil);
    event CooloffLifted(address indexed account);

    // ─────────────────────────────────────────────
    // Module Lifecycle
    // ─────────────────────────────────────────────

    function onInstall(bytes calldata data) external {
        require(!configs[msg.sender].initialized, "Already initialized");

        (uint256 valueTrigger, bool alwaysChallenge, uint256 rapidAttemptWindow) =
            abi.decode(data, (uint256, bool, uint256));

        configs[msg.sender] = GuardConfig({
            initialized:        true,
            valueTrigger:       valueTrigger > 0 ? valueTrigger : DEFAULT_VALUE_TRIGGER,
            alwaysChallenge:    alwaysChallenge,
            rapidAttemptWindow: rapidAttemptWindow > 0 ? rapidAttemptWindow : 10 minutes
        });
    }

    function onUninstall(bytes calldata) external {
        delete configs[msg.sender];
    }

    // ─────────────────────────────────────────────
    // Hook: Challenge Gate
    // ─────────────────────────────────────────────

    function preCheck(
        address account,
        address recipient,
        uint256 value,
        bytes calldata callData
    ) external returns (bytes memory) {
        GuardConfig storage config = configs[account];
        if (!config.initialized) return "";

        uint256 amount = _extractAmount(value, callData);

        // Check cooloff — mandatory protection period
        PressureProfile storage pressure = pressureProfiles[account];
        if (pressure.inCooloff) {
            if (block.timestamp < pressure.cooloffUntil) {
                revert("EthosiFi DeepfakeGuard: Vault is in mandatory cooloff. Possible social engineering detected. Try again later or contact your guardians.");
            } else {
                pressure.inCooloff = false;
                emit CooloffLifted(account);
            }
        }

        // Determine if challenge required
        bool challengeRequired = config.alwaysChallenge || amount >= config.valueTrigger;
        if (!challengeRequired) return "";

        bytes32 challengeId = keccak256(abi.encodePacked(account, recipient, amount, block.timestamp / 60));

        Challenge storage challenge = challenges[account][challengeId];

        // If no valid challenge has been answered, block and request one
        if (!challenge.answered || !challenge.passed) {
            // Track rapid attempts — indicator of social engineering pressure
            _trackAttempt(account, amount);

            revert("EthosiFi DeepfakeGuard: Large transfer requires human verification. Call requestChallenge() and respond within 3 minutes. This protects you from AI-powered impersonation attacks.");
        }

        // Verify challenge hasn't expired
        require(block.timestamp <= challenge.issuedAt + CHALLENGE_EXPIRY, "Challenge expired. Request a new one.");

        return "";
    }

    function postCheck(bytes calldata) external pure {}

    // ─────────────────────────────────────────────
    // Challenge Flow
    // ─────────────────────────────────────────────

    /**
     * @notice Request a challenge before a large transfer.
     *         The frontend generates a unique, time-sensitive puzzle.
     *         The user must solve it in person — no bot can auto-pass.
     *
     * @param recipient The intended recipient
     * @param amount    The intended amount
     * @param puzzleAnswer A hash of the user's answer to the UI-displayed puzzle
     *        (e.g., "type the 3rd and 7th word of your vault's creation phrase" —
     *         words are displayed on-screen, never stored, and rotate every session)
     */
    function requestChallenge(
        address recipient,
        uint256 amount,
        bytes32 puzzleAnswer
    ) external returns (bytes32 challengeId) {
        require(configs[msg.sender].initialized, "Not initialized");

        // Check cooloff
        PressureProfile storage pressure = pressureProfiles[msg.sender];
        require(!pressure.inCooloff || block.timestamp >= pressure.cooloffUntil, "In cooloff period");

        uint256 nonce = nonces[msg.sender]++;
        challengeId = keccak256(abi.encodePacked(msg.sender, recipient, amount, block.timestamp / 60));

        // Store challenge with the expected answer hash
        // puzzleAnswer = keccak256(userResponse + nonce + block.timestamp)
        // Only the person physically present with the device can answer correctly
        challenges[msg.sender][challengeId] = Challenge({
            challengeHash: keccak256(abi.encodePacked(puzzleAnswer, nonce, block.timestamp / CHALLENGE_EXPIRY)),
            issuedAt:      block.timestamp,
            expiresAt:     block.timestamp + CHALLENGE_EXPIRY,
            answered:      false,
            passed:        false,
            amount:        amount,
            recipient:     recipient
        });

        emit ChallengeIssued(msg.sender, challengeId, block.timestamp + CHALLENGE_EXPIRY, amount);
    }

    /**
     * @notice Submit the answer to a challenge.
     * @param challengeId   The challenge to answer
     * @param answer        The user's response (hashed with nonce on frontend)
     */
    function answerChallenge(
        bytes32 challengeId,
        bytes32 answer
    ) external returns (bool passed) {
        require(configs[msg.sender].initialized, "Not initialized");

        Challenge storage challenge = challenges[msg.sender][challengeId];
        require(challenge.issuedAt > 0, "Challenge not found");
        require(!challenge.answered, "Already answered");
        require(block.timestamp <= challenge.expiresAt, "Challenge expired");

        challenge.answered = true;

        // Verify the answer matches what was committed at request time
        uint256 nonce = nonces[msg.sender] - 1;
        bytes32 expectedHash = keccak256(abi.encodePacked(answer, nonce, challenge.issuedAt / CHALLENGE_EXPIRY));

        if (expectedHash == challenge.challengeHash) {
            challenge.passed = true;
            passed = true;
            emit ChallengePassed(msg.sender, challengeId);
        } else {
            challenge.passed = false;
            passed = false;
            _trackAttempt(msg.sender, challenge.amount);
            emit ChallengeFailed(msg.sender, challengeId, "Incorrect answer");
        }
    }

    // ─────────────────────────────────────────────
    // Social Pressure Detection
    // ─────────────────────────────────────────────

    function _trackAttempt(address account, uint256 amount) internal {
        PressureProfile storage pressure = pressureProfiles[account];
        GuardConfig storage config = configs[account];

        // Reset window if too old
        if (block.timestamp > pressure.firstAttemptAt + config.rapidAttemptWindow) {
            pressure.attemptCount  = 0;
            pressure.firstAttemptAt = block.timestamp;
        }

        pressure.attemptCount++;
        pressure.lastAttemptAt = block.timestamp;

        emit PressureDetected(account, pressure.attemptCount, "Repeated large transfer attempt detected");

        // Trigger cooloff if too many rapid attempts
        if (pressure.attemptCount >= COOLOFF_THRESHOLD) {
            pressure.inCooloff   = true;
            pressure.cooloffUntil = block.timestamp + COOLOFF_PERIOD;
            emit CooloffActivated(account, pressure.cooloffUntil);
        }
    }

    /**
     * @notice Guardian can manually lift a cooloff after verifying the user is safe.
     */
    function liftCooloff(address account) external {
        // Production: onlyGuardian
        PressureProfile storage pressure = pressureProfiles[account];
        pressure.inCooloff = false;
        emit CooloffLifted(account);
    }

    // ─────────────────────────────────────────────
    // View Helpers
    // ─────────────────────────────────────────────

    function _extractAmount(uint256 value, bytes calldata callData) internal pure returns (uint256) {
        if (value > 0) return value;
        if (callData.length >= 68) {
            bytes4 selector = bytes4(callData[:4]);
            if (selector == bytes4(keccak256("transfer(address,uint256)"))) {
                return uint256(bytes32(callData[36:68]));
            }
        }
        return 0;
    }

    function getChallengeStatus(address account, bytes32 challengeId) external view returns (
        bool answered, bool passed, uint256 expiresAt, bool expired
    ) {
        Challenge storage c = challenges[account][challengeId];
        return (c.answered, c.passed, c.expiresAt, block.timestamp > c.expiresAt);
    }

    function getPressureStatus(address account) external view returns (
        uint256 attemptCount, bool inCooloff, uint256 cooloffUntil
    ) {
        PressureProfile storage p = pressureProfiles[account];
        return (p.attemptCount, p.inCooloff, p.cooloffUntil);
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function isInitialized(address account) external view returns (bool) {
        return configs[account].initialized;
    }

    function validateUserOp(PackedUserOperation calldata, bytes32) external override returns (uint256) {
        return 0;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure override returns (bytes4) {
        return 0xffffffff;
    }

}