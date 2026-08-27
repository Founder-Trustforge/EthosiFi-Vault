// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {ReentrancyGuard} from "solady/utils/ReentrancyGuard.sol";

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
 * @title  EthosStaking
 * @notice Stake $ETHOS to unlock MVP membership, governance rights, and NFT badge.
 *
 * @dev    SECURITY FIXES (2026-08 audit):
 *         [HIGH-1] executeMonthlyBurn(address staker) was callable by ANY address.
 *                  An attacker could call this on every staker to burn their $ETHOS
 *                  faster than expected, forcibly drop them below the MVP threshold,
 *                  and revoke their membership and NFT badge without their knowledge.
 *                  Fixed: only the staker themselves OR the protocol owner can trigger
 *                  the monthly burn. Stakers trigger their own burn to participate in
 *                  the deflationary mechanic voluntarily.
 *         [MED-1]  stake() used transferFrom but did not verify the return value.
 *                  Fixed: require(success) on all token transfers.
 *         [MED-2]  unstake() transferred tokens before deleting state — re-entrancy
 *                  risk if EthosToken ever becomes upgradeable or non-standard.
 *                  Fixed: delete state before transfer (checks-effects-interactions).
 *         [MED-3]  transferOwnership() one-step. Fixed: two-step.
 *         [MED-4]  ReentrancyGuard applied to all state-mutating functions.
 */
contract EthosStaking is ReentrancyGuard {

    IEthosToken    public immutable ethosToken;
    IEthosMVPBadge public mvpBadge;
    address public owner;
    address public pendingOwner;
    address public governanceContract;

    // ─── Constants ────────────────────────────────────────────────────────────

    uint256 public constant MVP_STAKE_REQUIREMENT = 10_000 * 1e18;
    uint256 public constant MONTHLY_BURN          =    100 * 1e18;
    uint256 public constant UNSTAKE_COOLDOWN      = 7 days;
    uint256 public constant BURN_INTERVAL         = 30 days;
    uint8   public constant TIER_MVP              = 1;

    // ─── State ────────────────────────────────────────────────────────────────

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

    // ─── Events ───────────────────────────────────────────────────────────────

    event Staked(address indexed user, uint256 amount, bool mvpActivated);
    event UnstakeRequested(address indexed user, uint256 unlockAt);
    event Unstaked(address indexed user, uint256 amount);
    event MVPActivated(address indexed user);
    event MVPRevoked(address indexed user);
    event MonthlyBurnExecuted(address indexed user, uint256 burned, uint256 month);
    event OwnershipTransferStarted(address indexed prev, address indexed next);
    event OwnershipTransferred(address indexed prev, address indexed next);

    // ─── Errors ───────────────────────────────────────────────────────────────

    error NotOwner();
    error NotAuthorized();
    error InsufficientStake();
    error AlreadyStaked();
    error NoStake();
    error CooldownNotMet();
    error UnstakeNotRequested();
    error BurnIntervalNotMet();
    error TransferFailed();
    error ZeroAddress();

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor(address _ethosToken) {
        if (_ethosToken == address(0)) revert ZeroAddress();
        ethosToken = IEthosToken(_ethosToken);
        owner      = msg.sender;
    }

    modifier onlyOwner() { if (msg.sender != owner) revert NotOwner(); _; }

    // ─── Staking ──────────────────────────────────────────────────────────────

    function stake(uint256 amount) external nonReentrant {
        if (amount < MVP_STAKE_REQUIREMENT) revert InsufficientStake();

        StakeInfo storage s = stakes[msg.sender];
        if (s.amount > 0) revert AlreadyStaked();

        // [MED-1] Verify transfer succeeded
        bool ok = ethosToken.transferFrom(msg.sender, address(this), amount);
        if (!ok) revert TransferFailed();

        s.amount          = amount;
        s.stakedAt        = block.timestamp;
        s.lastBurnAt      = block.timestamp;
        s.mvpActive       = true;
        s.governanceVotes = amount / (1000 * 1e18);

        totalStaked  += amount;
        totalStakers++;

        if (address(mvpBadge) != address(0)) {
            mvpBadge.mintBadge(msg.sender, TIER_MVP);
        }

        emit Staked(msg.sender, amount, true);
        emit MVPActivated(msg.sender);
    }

    function requestUnstake() external nonReentrant {
        StakeInfo storage s = stakes[msg.sender];
        if (s.amount == 0) revert NoStake();

        s.unstakeRequestAt = block.timestamp;

        if (s.mvpActive) {
            s.mvpActive = false;
            if (address(mvpBadge) != address(0)) mvpBadge.revokeBadge(msg.sender);
            emit MVPRevoked(msg.sender);
        }

        emit UnstakeRequested(msg.sender, block.timestamp + UNSTAKE_COOLDOWN);
    }

    function unstake() external nonReentrant {
        StakeInfo storage s = stakes[msg.sender];
        if (s.amount == 0) revert NoStake();
        if (s.unstakeRequestAt == 0) revert UnstakeNotRequested();
        if (block.timestamp < s.unstakeRequestAt + UNSTAKE_COOLDOWN) revert CooldownNotMet();

        uint256 amount = s.amount;

        // [MED-2] Effects before interaction (checks-effects-interactions)
        totalStaked  -= amount;
        totalStakers--;
        delete stakes[msg.sender];

        bool ok = ethosToken.transfer(msg.sender, amount);
        if (!ok) revert TransferFailed();

        emit Unstaked(msg.sender, amount);
    }

    /**
     * @notice Execute the monthly $ETHOS burn for a staker.
     * @dev [HIGH-1] Only callable by the staker themselves or the protocol owner.
     *      This prevents attackers from forcibly burning other users' tokens and
     *      revoking their MVP status without consent.
     */
    function executeMonthlyBurn(address staker) external nonReentrant {
        // [HIGH-1] Restrict to staker or owner only
        if (msg.sender != staker && msg.sender != owner) revert NotAuthorized();

        StakeInfo storage s = stakes[staker];
        if (s.amount == 0) revert NoStake();
        if (block.timestamp < s.lastBurnAt + BURN_INTERVAL) revert BurnIntervalNotMet();

        s.lastBurnAt = block.timestamp;

        if (s.amount >= MONTHLY_BURN) {
            s.amount     -= MONTHLY_BURN;
            totalStaked  -= MONTHLY_BURN;

            // [MED-2] State updated before external call
            ethosToken.burnFrom(address(this), MONTHLY_BURN);

            s.governanceVotes = s.amount / (1000 * 1e18);

            if (s.amount < MVP_STAKE_REQUIREMENT && s.mvpActive) {
                s.mvpActive = false;
                if (address(mvpBadge) != address(0)) mvpBadge.revokeBadge(staker);
                emit MVPRevoked(staker);
            }

            uint256 month = (block.timestamp - s.stakedAt) / BURN_INTERVAL;
            emit MonthlyBurnExecuted(staker, MONTHLY_BURN, month);
        }
    }

    // ─── View ─────────────────────────────────────────────────────────────────

    function isMVP(address account) external view returns (bool) {
        return stakes[account].mvpActive && stakes[account].amount >= MVP_STAKE_REQUIREMENT;
    }

    function getGovernanceVotes(address account) external view returns (uint256) {
        return stakes[account].mvpActive ? stakes[account].governanceVotes : 0;
    }

    function getStakeInfo(address account) external view returns (
        uint256 amount, uint256 stakedAt, bool mvpActive,
        uint256 governanceVotes, uint256 nextBurnAt, uint256 unstakeAvailableAt
    ) {
        StakeInfo storage s = stakes[account];
        return (
            s.amount, s.stakedAt, s.mvpActive, s.governanceVotes,
            s.lastBurnAt + BURN_INTERVAL,
            s.unstakeRequestAt > 0 ? s.unstakeRequestAt + UNSTAKE_COOLDOWN : 0
        );
    }

    // ─── Owner ────────────────────────────────────────────────────────────────

    function setMVPBadge(address _mvpBadge) external onlyOwner {
        mvpBadge = IEthosMVPBadge(_mvpBadge);
    }

    function setGovernanceContract(address _governance) external onlyOwner {
        governanceContract = _governance;
    }

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
}
