// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

interface IEthosToken {
    function burnFrom(address from, uint256 amount) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function SUBSCRIPTION_BURN() external view returns (uint256);
}

interface IEthosMVPBadge {
    function mintBadge(address to, uint8 tier) external;
    function revokeBadge(address from) external;
    function hasBadge(address account) external view returns (bool);
}

/**
 * @title EthosStaking
 * @notice Stake $ETHOS to unlock MVP membership, governance rights, and NFT badge
 * @dev
 * Tiers:
 * - MVP: Stake 10,000 $ETHOS → Free Pro membership + NFT badge + governance
 * - 7-day unstaking cooldown
 * - 100 $ETHOS burned monthly from staking rewards
 *
 * EthosiFi Vault — The Unstealable Wallet
 */
contract EthosStaking {

    IEthosToken   public immutable ethosToken;
    IEthosMVPBadge public mvpBadge;
    address public owner;
    address public governanceContract;

    // ─── CONSTANTS ───────────────────────────────────────────────────────────

    uint256 public constant MVP_STAKE_REQUIREMENT = 10_000 * 1e18;
    uint256 public constant MONTHLY_BURN          = 100 * 1e18;
    uint256 public constant UNSTAKE_COOLDOWN      = 7 days;
    uint256 public constant BURN_INTERVAL         = 30 days;

    uint8 public constant TIER_MVP = 1;
    uint8 public constant TIER_LP  = 2; // Reserved for LP Manager

    // ─── STATE ───────────────────────────────────────────────────────────────

    struct StakeInfo {
        uint256 amount;
        uint256 stakedAt;
        uint256 lastBurnAt;
        uint256 unstakeRequestAt;
        bool    mvpActive;
        uint256 governanceVotes;
    }

    mapping(address => StakeInfo) public stakes;
    uint256 public totalStaked;
    uint256 public totalStakers;

    // ─── EVENTS ──────────────────────────────────────────────────────────────

    event Staked(address indexed user, uint256 amount, bool mvpActivated);
    event UnstakeRequested(address indexed user, uint256 unlockAt);
    event Unstaked(address indexed user, uint256 amount);
    event MVPActivated(address indexed user);
    event MVPRevoked(address indexed user);
    event MonthlyBurnExecuted(address indexed user, uint256 burned, uint256 month);

    // ─── ERRORS ──────────────────────────────────────────────────────────────

    error NotOwner();
    error InsufficientStake();
    error AlreadyStaked();
    error NoStake();
    error CooldownNotMet();
    error UnstakeNotRequested();
    error BurnIntervalNotMet();
    error ZeroAddress();

    // ─── CONSTRUCTOR ─────────────────────────────────────────────────────────

    constructor(address _ethosToken) {
        ethosToken = IEthosToken(_ethosToken);
        owner = msg.sender;
    }

    // ─── STAKING FUNCTIONS ───────────────────────────────────────────────────

    /**
     * @notice Stake $ETHOS to become an MVP member
     * @param amount Amount to stake (minimum 10,000 $ETHOS for MVP)
     */
    function stake(uint256 amount) external {
        if (amount < MVP_STAKE_REQUIREMENT) revert InsufficientStake();

        StakeInfo storage s = stakes[msg.sender];
        if (s.amount > 0) revert AlreadyStaked();

        ethosToken.transferFrom(msg.sender, address(this), amount);

        s.amount = amount;
        s.stakedAt = block.timestamp;
        s.lastBurnAt = block.timestamp;
        s.mvpActive = true;
        s.governanceVotes = amount / (1000 * 1e18); // 1 vote per 1000 $ETHOS staked

        totalStaked += amount;
        totalStakers++;

        // Mint MVP NFT badge
        if (address(mvpBadge) != address(0)) {
            mvpBadge.mintBadge(msg.sender, TIER_MVP);
        }

        emit Staked(msg.sender, amount, true);
        emit MVPActivated(msg.sender);
    }

    /**
     * @notice Request unstaking — starts 7-day cooldown
     */
    function requestUnstake() external {
        StakeInfo storage s = stakes[msg.sender];
        if (s.amount == 0) revert NoStake();

        s.unstakeRequestAt = block.timestamp;

        // Revoke MVP status immediately on unstake request
        if (s.mvpActive) {
            s.mvpActive = false;
            if (address(mvpBadge) != address(0)) {
                mvpBadge.revokeBadge(msg.sender);
            }
            emit MVPRevoked(msg.sender);
        }

        emit UnstakeRequested(msg.sender, block.timestamp + UNSTAKE_COOLDOWN);
    }

    /**
     * @notice Complete unstaking after cooldown period
     */
    function unstake() external {
        StakeInfo storage s = stakes[msg.sender];
        if (s.amount == 0) revert NoStake();
        if (s.unstakeRequestAt == 0) revert UnstakeNotRequested();
        if (block.timestamp < s.unstakeRequestAt + UNSTAKE_COOLDOWN) revert CooldownNotMet();

        uint256 amount = s.amount;
        totalStaked -= amount;
        totalStakers--;

        delete stakes[msg.sender];

        ethosToken.transfer(msg.sender, amount);

        emit Unstaked(msg.sender, amount);
    }

    /**
     * @notice Execute monthly burn for a staker (100 $ETHOS burned)
     * @dev Anyone can trigger this — incentivized by protocol health
     */
    function executeMonthlyBurn(address staker) external {
        StakeInfo storage s = stakes[staker];
        if (s.amount == 0) revert NoStake();
        if (block.timestamp < s.lastBurnAt + BURN_INTERVAL) revert BurnIntervalNotMet();

        s.lastBurnAt = block.timestamp;

        // Burn 100 $ETHOS from staker's staked amount
        if (s.amount >= MONTHLY_BURN) {
            s.amount -= MONTHLY_BURN;
            totalStaked -= MONTHLY_BURN;
            ethosToken.burnFrom(address(this), MONTHLY_BURN);

            // Recalculate governance votes
            s.governanceVotes = s.amount / (1000 * 1e18);

            // Check if still above MVP threshold
            if (s.amount < MVP_STAKE_REQUIREMENT && s.mvpActive) {
                s.mvpActive = false;
                if (address(mvpBadge) != address(0)) {
                    mvpBadge.revokeBadge(staker);
                }
                emit MVPRevoked(staker);
            }

            uint256 month = (block.timestamp - s.stakedAt) / BURN_INTERVAL;
            emit MonthlyBurnExecuted(staker, MONTHLY_BURN, month);
        }
    }

    // ─── VIEW FUNCTIONS ──────────────────────────────────────────────────────

    function isMVP(address account) external view returns (bool) {
        return stakes[account].mvpActive && stakes[account].amount >= MVP_STAKE_REQUIREMENT;
    }

    function getGovernanceVotes(address account) external view returns (uint256) {
        return stakes[account].mvpActive ? stakes[account].governanceVotes : 0;
    }

    function getStakeInfo(address account) external view returns (
        uint256 amount,
        uint256 stakedAt,
        bool mvpActive,
        uint256 governanceVotes,
        uint256 nextBurnAt,
        uint256 unstakeAvailableAt
    ) {
        StakeInfo storage s = stakes[account];
        amount = s.amount;
        stakedAt = s.stakedAt;
        mvpActive = s.mvpActive;
        governanceVotes = s.governanceVotes;
        nextBurnAt = s.lastBurnAt + BURN_INTERVAL;
        unstakeAvailableAt = s.unstakeRequestAt > 0 ? s.unstakeRequestAt + UNSTAKE_COOLDOWN : 0;
    }

    // ─── OWNER FUNCTIONS ─────────────────────────────────────────────────────

    function setMVPBadge(address _mvpBadge) external {
        if (msg.sender != owner) revert NotOwner();
        mvpBadge = IEthosMVPBadge(_mvpBadge);
    }

    function setGovernanceContract(address _governance) external {
        if (msg.sender != owner) revert NotOwner();
        governanceContract = _governance;
    }

    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert NotOwner();
        if (newOwner == address(0)) revert ZeroAddress();
        owner = newOwner;
    }
}
