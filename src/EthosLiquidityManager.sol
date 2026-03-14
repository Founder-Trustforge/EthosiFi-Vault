// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

interface IEthosToken {
    function burnSubscriptionFee(address subscriber) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function SUBSCRIPTION_BURN() external view returns (uint256);
}

interface IEthosMVPBadge {
    function mintBadge(address to, uint8 tier) external;
    function revokeBadge(address from) external;
    function upgradeBadge(address holder) external;
    function hasBadge(address account) external view returns (bool);
    function getBadgeTier(address account) external view returns (uint8);
}

/**
 * @title EthosLiquidityManager
 * @notice Manages LP provider membership, burns, and badge upgrades
 * @dev
 * LP Providers:
 * - Add minimum $500 USDC equivalent to $ETHOS/USDC Uniswap V3 pool
 * - Receive Gold tier MVP badge
 * - Get free Pro membership
 * - 100 $ETHOS burned monthly
 * - Earn trading fees from pool
 *
 * EthosiFi Vault — The Unstealable Wallet
 */
contract EthosLiquidityManager {

    IEthosToken    public immutable ethosToken;
    IEthosMVPBadge public mvpBadge;
    address public owner;
    address public uniswapPool; // $ETHOS/USDC Uniswap V3 pool

    // ─── CONSTANTS ───────────────────────────────────────────────────────────

    uint256 public constant MIN_LP_USD_VALUE    = 500e6;  // $500 USDC (6 decimals)
    uint256 public constant MONTHLY_BURN        = 100 * 1e18;
    uint256 public constant BURN_INTERVAL       = 30 days;
    uint8   public constant TIER_LP             = 2;

    // ─── STATE ───────────────────────────────────────────────────────────────

    struct LPInfo {
        uint256 ethosProvided;
        uint256 usdcProvided;
        uint256 registeredAt;
        uint256 lastBurnAt;
        bool    active;
        uint256 totalBurned;
    }

    mapping(address => LPInfo) public lpProviders;
    uint256 public totalLPProviders;
    uint256 public totalEthosInLP;

    // ─── EVENTS ──────────────────────────────────────────────────────────────

    event LPRegistered(address indexed provider, uint256 ethosAmount, uint256 usdcAmount);
    event LPRemoved(address indexed provider);
    event LPBurnExecuted(address indexed provider, uint256 burned);
    event PoolSet(address indexed pool);

    // ─── ERRORS ──────────────────────────────────────────────────────────────

    error NotOwner();
    error InsufficientLPValue();
    error AlreadyRegistered();
    error NotRegistered();
    error BurnIntervalNotMet();
    error ZeroAddress();

    // ─── CONSTRUCTOR ─────────────────────────────────────────────────────────

    constructor(address _ethosToken) {
        ethosToken = IEthosToken(_ethosToken);
        owner = msg.sender;
    }

    // ─── LP FUNCTIONS ────────────────────────────────────────────────────────

    /**
     * @notice Register as an LP provider to receive Gold MVP badge and free Pro membership
     * @param ethosAmount Amount of $ETHOS provided to pool
     * @param usdcAmount Amount of USDC provided to pool (must be >= $500)
     */
    function registerLP(uint256 ethosAmount, uint256 usdcAmount) external {
        if (usdcAmount < MIN_LP_USD_VALUE) revert InsufficientLPValue();

        LPInfo storage lp = lpProviders[msg.sender];
        if (lp.active) revert AlreadyRegistered();

        lp.ethosProvided = ethosAmount;
        lp.usdcProvided  = usdcAmount;
        lp.registeredAt  = block.timestamp;
        lp.lastBurnAt    = block.timestamp;
        lp.active        = true;

        totalLPProviders++;
        totalEthosInLP += ethosAmount;

        // Mint or upgrade to Gold LP badge
        if (address(mvpBadge) != address(0)) {
            if (mvpBadge.hasBadge(msg.sender)) {
                mvpBadge.upgradeBadge(msg.sender);
            } else {
                mvpBadge.mintBadge(msg.sender, TIER_LP);
            }
        }

        emit LPRegistered(msg.sender, ethosAmount, usdcAmount);
    }

    /**
     * @notice Remove LP position and revoke Gold badge
     */
    function removeLP() external {
        LPInfo storage lp = lpProviders[msg.sender];
        if (!lp.active) revert NotRegistered();

        totalEthosInLP -= lp.ethosProvided;
        totalLPProviders--;

        lp.active = false;

        // Revoke badge
        if (address(mvpBadge) != address(0) && mvpBadge.hasBadge(msg.sender)) {
            mvpBadge.revokeBadge(msg.sender);
        }

        emit LPRemoved(msg.sender);
    }

    /**
     * @notice Execute monthly burn for LP provider (100 $ETHOS burned)
     */
    function executeMonthlyBurn(address provider) external {
        LPInfo storage lp = lpProviders[provider];
        if (!lp.active) revert NotRegistered();
        if (block.timestamp < lp.lastBurnAt + BURN_INTERVAL) revert BurnIntervalNotMet();

        lp.lastBurnAt = block.timestamp;
        lp.totalBurned += MONTHLY_BURN;

        ethosToken.burnSubscriptionFee(provider);

        emit LPBurnExecuted(provider, MONTHLY_BURN);
    }

    /**
     * @notice Batch execute monthly burns for multiple providers
     */
    function batchExecuteBurns(address[] calldata providers) external {
        for (uint256 i = 0; i < providers.length; i++) {
            LPInfo storage lp = lpProviders[providers[i]];
            if (lp.active && block.timestamp >= lp.lastBurnAt + BURN_INTERVAL) {
                lp.lastBurnAt = block.timestamp;
                lp.totalBurned += MONTHLY_BURN;
                ethosToken.burnSubscriptionFee(providers[i]);
                emit LPBurnExecuted(providers[i], MONTHLY_BURN);
            }
        }
    }

    // ─── VIEW FUNCTIONS ──────────────────────────────────────────────────────

    function isActiveLP(address provider) external view returns (bool) {
        return lpProviders[provider].active;
    }

    function getLPInfo(address provider) external view returns (
        uint256 ethosProvided,
        uint256 usdcProvided,
        uint256 registeredAt,
        uint256 nextBurnAt,
        bool active,
        uint256 totalBurned
    ) {
        LPInfo storage lp = lpProviders[provider];
        ethosProvided = lp.ethosProvided;
        usdcProvided  = lp.usdcProvided;
        registeredAt  = lp.registeredAt;
        nextBurnAt    = lp.lastBurnAt + BURN_INTERVAL;
        active        = lp.active;
        totalBurned   = lp.totalBurned;
    }

    // ─── OWNER FUNCTIONS ─────────────────────────────────────────────────────

    function setMVPBadge(address _mvpBadge) external {
        if (msg.sender != owner) revert NotOwner();
        mvpBadge = IEthosMVPBadge(_mvpBadge);
    }

    function setUniswapPool(address _pool) external {
        if (msg.sender != owner) revert NotOwner();
        if (_pool == address(0)) revert ZeroAddress();
        uniswapPool = _pool;
        emit PoolSet(_pool);
    }

    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert NotOwner();
        if (newOwner == address(0)) revert ZeroAddress();
        owner = newOwner;
    }
}
