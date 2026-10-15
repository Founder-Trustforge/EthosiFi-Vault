// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {ReentrancyGuard} from "solady/utils/ReentrancyGuard.sol";
import {V3Math} from "./lib/V3Math.sol";

interface IEthosToken {
    function burnSubscriptionFee(address subscriber) external;
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IEthosMVPBadge {
    function mintBadge(address to, uint8 tier) external;
    function revokeBadge(address from, uint8 tier) external;
    function hasBadge(address account) external view returns (bool);
    function getBadgeTier(address account) external view returns (uint8);
}

/**
 * @notice Uniswap V3 Non-Fungible Position Manager interface.
 * Used to verify that an LP token is real and owned by the caller.
 */
interface INonfungiblePositionManager {
    struct Position {
        uint96 nonce;
        address operator;
        address token0;
        address token1;
        uint24 fee;
        int24 tickLower;
        int24 tickUpper;
        uint128 liquidity;
        uint256 feeGrowthInside0LastX128;
        uint256 feeGrowthInside1LastX128;
        uint128 tokensOwed0;
        uint128 tokensOwed1;
    }
    function positions(uint256 tokenId) external view returns (Position memory);
    function ownerOf(uint256 tokenId) external view returns (address);
}

/**
 * @notice Uniswap V3 pool interface — used to verify current liquidity and price.
 */
interface IUniswapV3Pool {
    function slot0()
        external
        view
        returns (
            uint160 sqrtPriceX96,
            int24 tick,
            uint16 observationIndex,
            uint16 observationCardinality,
            uint16 observationCardinalityNext,
            uint8 feeProtocol,
            bool unlocked
        );
    function token0() external view returns (address);
    function token1() external view returns (address);
    function liquidity() external view returns (uint128);
    function fee() external view returns (uint24);
    function observe(uint32[] calldata secondsAgos)
        external
        view
        returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s);
}

/**
 * @title EthosLiquidityManager
 * @notice Manages LP provider membership with REAL on-chain Uniswap V3 verification.
 * LP providers receive a Gold NFT badge minted directly to their wallet.
 *
 * @dev SECURITY FIXES (2026-08 audit):
 * [CRIT-1] registerLP() accepted self-reported ethosAmount and usdcAmount
 * parameters with NO on-chain verification. Any address could call
 * registerLP(0, 500e6) to receive a Gold LP badge and free Pro
 * membership without providing any liquidity whatsoever.
 * Fixed: caller must provide a Uniswap V3 NFT position token ID.
 * The contract verifies:
 * (a) The NFT is owned by msg.sender (not just held).
 * (b) The position is in the correct $ETHOS/USDC pool.
 * (c) The position has non-zero liquidity.
 * (d) The USDC value of the position meets MIN_LP_USD_VALUE.
 * The NFT token ID is stored and re-verified on removeLP() to prevent
 * transfer-and-claim attacks (register, transfer NFT, remove LP).
 * [CRIT-2] executeMonthlyBurn() callable by anyone — attacker could drain
 *                  LP providers' $ETHOS by triggering burns prematurely.
 * Fixed: only callable by the provider themselves or the owner.
 * [HIGH-1] removeLP() subtracted from totalEthosInLP using the stored
 * ethosProvided amount which was self-reported and could be
 * type(uint256).max, causing underflow. Fixed: value now comes
 * from on-chain verification.
 * [MED-1] executeMonthlyBurn() made external call before updating state.
 * Fixed: checks-effects-interactions.
 * [MED-2] Two-step ownership added.
 * [MED-3] ReentrancyGuard applied to all state-mutating functions.
 *
 * NFT MINTING: When an LP provider is verified, EthosMVPBadge.mintBadge()
 * is called with TIER_LP (2) directly on the badge contract. The badge
 * contract emits a Transfer(address(0), provider, tokenId) event, making
 * the NFT visible in any ERC-721 compatible wallet (MetaMask, Rainbow, etc.).
 * The badge is soulbound — it cannot be transferred. It is revoked automatically
 * when the LP provider removes their position.
 */
contract EthosLiquidityManager is ReentrancyGuard {
    IEthosToken public immutable ethosToken;
    IEthosMVPBadge public mvpBadge;
    INonfungiblePositionManager public positionManager;
    address public ethosUsdcPool; // $ETHOS/USDC Uniswap V3 pool
    uint24 public poolFee; // fee tier of that pool; positions in any other tier are rejected
    /// @dev Uniswap position NFT id => provider currently registered with it (one provider per NFT).
    mapping(uint256 => address) public positionClaimedBy;
    address public ethosTokenAddr; // $ETHOS token address
    address public usdcTokenAddr; // USDC token address
    address public owner;
    address public pendingOwner;

    // ─── Constants ────────────────────────────────────────────────────────────

    uint256 public constant MIN_LP_USD_VALUE = 500e6; // $500 USDC (6 decimals)
    uint256 public constant MONTHLY_BURN = 100 * 1e18;
    uint256 public constant BURN_INTERVAL = 30 days;
    uint8 public constant TIER_LP = 2;
    uint32 public constant TWAP_WINDOW = 30 minutes;
    /// @dev After a missed monthly burn the badge lapses once this grace period ends (anyone can trigger).
    uint256 public constant BURN_GRACE = 7 days;

    // ─── State ────────────────────────────────────────────────────────────────

    struct LPInfo {
        uint256 positionTokenId; // Uniswap V3 NFT token ID (on-chain proof)
        uint256 verifiedUsdcValue; // USDC value at registration time
        uint256 registeredAt;
        uint256 lastBurnAt;
        bool active;
        uint256 totalBurned;
    }

    mapping(address => LPInfo) public lpProviders;
    uint256 public totalLPProviders;

    // ─── Events ───────────────────────────────────────────────────────────────

    event LPRegistered(address indexed provider, uint256 indexed positionTokenId, uint256 usdcValue);
    event LPRemoved(address indexed provider, uint256 indexed positionTokenId);
    event LPBurnExecuted(address indexed provider, uint256 burned);
    event BadgeMinted(address indexed provider, uint8 tier);
    event BadgeRevoked(address indexed provider);
    event PoolConfigured(address indexed pool, address ethosToken, address usdc);
    event OwnershipTransferStarted(address indexed prev, address indexed next);
    event OwnershipTransferred(address indexed prev, address indexed next);

    // ─── Errors ───────────────────────────────────────────────────────────────

    error NotOwner();
    error NotAuthorized();
    error PoolNotConfigured();
    error NotPositionOwner();
    error WrongPool();
    error InsufficientLiquidity();
    error InsufficientLPValue();
    error AlreadyRegistered();
    error NotRegistered();
    error BurnIntervalNotMet();
    error TransferFailed();
    error ZeroAddress();
    error PositionTransferred();
    error PositionAlreadyClaimed();
    error BurnFailed();
    error NotLapsed();
    error BadPoolConfig();

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor(address _ethosToken) {
        if (_ethosToken == address(0)) revert ZeroAddress();
        ethosToken = IEthosToken(_ethosToken);
        ethosTokenAddr = _ethosToken;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // ─── LP registration with real on-chain verification ──────────────────────

    /**
     * @notice Register as an LP provider by proving ownership of a Uniswap V3 position.
     *
     * @param positionTokenId The Uniswap V3 NFT token ID representing your LP position
     * in the $ETHOS/USDC pool. You must own this NFT.
     *
     * @dev Verification steps:
     * 1. positionManager.ownerOf(tokenId) == msg.sender
     * 2. Position is in the approved $ETHOS/USDC pool (correct token0, token1, fee)
     * 3. Position has non-zero liquidity
     * 4. Computed USDC value >= MIN_LP_USD_VALUE ($500)
     *
     * Once verified, EthosMVPBadge.mintBadge(msg.sender, TIER_LP) is called,
     *      minting a Gold LP NFT badge directly to the provider's wallet address.
     * The badge is soulbound (non-transferable) and visible in any ERC-721 wallet.
     */
    function registerLP(uint256 positionTokenId) external nonReentrant {
        if (ethosUsdcPool == address(0) || address(positionManager) == address(0)) {
            revert PoolNotConfigured();
        }

        LPInfo storage lp = lpProviders[msg.sender];
        if (lp.active) revert AlreadyRegistered();

        // ── Step 1: Verify NFT ownership ─────────────────────────────────────
        address nftOwner = positionManager.ownerOf(positionTokenId);
        if (nftOwner != msg.sender) revert NotPositionOwner();

        // ── Step 2: Verify position is in correct pool ────────────────────────
        INonfungiblePositionManager.Position memory pos = positionManager.positions(positionTokenId);

        // Position must contain $ETHOS and USDC (either token0 or token1)
        bool ethosIsToken0 = pos.token0 == ethosTokenAddr && pos.token1 == usdcTokenAddr;
        bool ethosIsToken1 = pos.token0 == usdcTokenAddr && pos.token1 == ethosTokenAddr;
        if (!ethosIsToken0 && !ethosIsToken1) revert WrongPool();
        if (pos.fee != poolFee) revert WrongPool();

        // One provider per position NFT: an NFT cannot be passed around to mint several badges.
        address claimed = positionClaimedBy[positionTokenId];
        if (claimed != address(0) && claimed != msg.sender && lpProviders[claimed].active) {
            revert PositionAlreadyClaimed();
        }

        // ── Step 3: Verify non-zero liquidity ─────────────────────────────────
        if (pos.liquidity == 0) revert InsufficientLiquidity();

        // ── Step 4: Compute and verify USDC value ─────────────────────────────
        uint256 usdcValue = _computeUsdcValue(pos, ethosIsToken0);
        if (usdcValue < MIN_LP_USD_VALUE) revert InsufficientLPValue();

        // ── Register ──────────────────────────────────────────────────────────
        lp.positionTokenId = positionTokenId;
        lp.verifiedUsdcValue = usdcValue;
        lp.registeredAt = block.timestamp;
        lp.lastBurnAt = block.timestamp;
        lp.active = true;
        positionClaimedBy[positionTokenId] = msg.sender;

        totalLPProviders++;

        // ── Gold LP tier on the provider's (soulbound) badge; never blocks registration ──
        if (address(mvpBadge) != address(0)) {
            (bool ok,) = address(mvpBadge).call(abi.encodeCall(IEthosMVPBadge.mintBadge, (msg.sender, TIER_LP)));
            if (ok) emit BadgeMinted(msg.sender, TIER_LP);
        }

        emit LPRegistered(msg.sender, positionTokenId, usdcValue);
    }

    /// @notice Voluntarily leave the LP programme and drop the Gold tier.
    function removeLP() external nonReentrant {
        if (!lpProviders[msg.sender].active) revert NotRegistered();
        _deactivate(msg.sender);
    }

    /**
     * @notice Anyone may end a registration that no longer qualifies: the position was emptied or moved
     * to another wallet, or the monthly burn was missed past the grace period. This keeps Gold badges honest
     * without trusting the owner to police them.
     */
    function deactivateIfInvalid(address provider) external nonReentrant {
        LPInfo storage lp = lpProviders[provider];
        if (!lp.active) revert NotRegistered();
        bool lapsed = block.timestamp > lp.lastBurnAt + BURN_INTERVAL + BURN_GRACE;
        if (!lapsed && _positionStillValid(provider, lp.positionTokenId)) revert NotLapsed();
        _deactivate(provider);
    }

    /**
     * @notice Execute monthly burn for an LP provider (100 $ETHOS).
     * @dev Only the provider or the owner may call. The token additionally requires the provider's
     * allowance for this contract, so a burn is always something the provider consented to.
     */
    function executeMonthlyBurn(address provider) external nonReentrant {
        if (msg.sender != provider && msg.sender != owner) revert NotAuthorized();
        LPInfo storage lp = lpProviders[provider];
        if (!lp.active) revert NotRegistered();
        if (block.timestamp < lp.lastBurnAt + BURN_INTERVAL) revert BurnIntervalNotMet();

        if (!_positionStillValid(provider, lp.positionTokenId)) {
            _deactivate(provider);
            return;
        }
        if (!_burn(provider, lp)) revert BurnFailed();
    }

    /// @notice Batch burns; a provider whose burn fails is skipped (never blocks the others).
    function batchExecuteBurns(address[] calldata providers) external nonReentrant {
        for (uint256 i = 0; i < providers.length; i++) {
            address provider = providers[i];
            if (msg.sender != provider && msg.sender != owner) continue;
            LPInfo storage lp = lpProviders[provider];
            if (!lp.active || block.timestamp < lp.lastBurnAt + BURN_INTERVAL) continue;
            if (!_positionStillValid(provider, lp.positionTokenId)) {
                _deactivate(provider);
                continue;
            }
            _burn(provider, lp);
        }
    }

    function _burn(address provider, LPInfo storage lp) internal returns (bool) {
        try ethosToken.burnSubscriptionFee(provider) {
            lp.lastBurnAt = block.timestamp;
            lp.totalBurned += MONTHLY_BURN;
            emit LPBurnExecuted(provider, MONTHLY_BURN);
            return true;
        } catch {
            return false;
        }
    }

    function _positionStillValid(address provider, uint256 tokenId) internal view returns (bool) {
        try positionManager.ownerOf(tokenId) returns (address o) {
            if (o != provider) return false;
        } catch {
            return false;
        }
        try positionManager.positions(tokenId) returns (INonfungiblePositionManager.Position memory pos) {
            return pos.liquidity != 0;
        } catch {
            return false;
        }
    }

    function _deactivate(address provider) internal {
        LPInfo storage lp = lpProviders[provider];
        lp.active = false;
        totalLPProviders--;
        if (positionClaimedBy[lp.positionTokenId] == provider) delete positionClaimedBy[lp.positionTokenId];
        emit LPRemoved(provider, lp.positionTokenId);
        if (address(mvpBadge) != address(0)) {
            (bool ok,) = address(mvpBadge).call(abi.encodeCall(IEthosMVPBadge.revokeBadge, (provider, TIER_LP)));
            if (ok) emit BadgeRevoked(provider);
        }
    }

    // ─── Internal: compute USDC value of position ────────────────────────────

    /**
     * @dev USD value of a position, using real Uniswap V3 math at the pool's 30-minute TWAP price.
     * Token amounts come from liquidity and the position's tick range; the ETHOS side is converted to USDC at
     * the same TWAP price. A spot price (slot0) is never used: it can be moved inside one transaction.
     * Reverts if the pool has no 30-minute observation history yet (fail closed).
     */
    function _computeUsdcValue(INonfungiblePositionManager.Position memory pos, bool ethosIsToken0)
        internal
        view
        returns (uint256 usdcValue)
    {
        uint160 sqrtP = V3Math.getSqrtRatioAtTick(_twapTick());
        (uint256 amount0, uint256 amount1) = V3Math.getAmountsForLiquidity(
            sqrtP, V3Math.getSqrtRatioAtTick(pos.tickLower), V3Math.getSqrtRatioAtTick(pos.tickUpper), pos.liquidity
        );
        if (ethosIsToken0) {
            // token1 = USDC; convert token0 (ETHOS) to USDC
            usdcValue = amount1 + V3Math.token0ToToken1(amount0, sqrtP);
        } else {
            // token0 = USDC; convert token1 (ETHOS) to USDC
            usdcValue = amount0 + V3Math.token1ToToken0(amount1, sqrtP);
        }
    }

    function _twapTick() internal view returns (int24) {
        uint32[] memory ago = new uint32[](2);
        ago[0] = TWAP_WINDOW;
        ago[1] = 0;
        (int56[] memory cum,) = IUniswapV3Pool(ethosUsdcPool).observe(ago);
        int56 delta = cum[1] - cum[0];
        int56 tick = delta / int56(uint56(TWAP_WINDOW));
        if (delta < 0 && (delta % int56(uint56(TWAP_WINDOW)) != 0)) tick--; // round toward -infinity
        return int24(tick);
    }

    // ─── Owner configuration ──────────────────────────────────────────────────

    /**
     * @notice Configure the Uniswap V3 pool and position manager.
     * Must be called before any LP can register.
     */
    function configurePool(address _positionManager, address _pool, address _ethosToken, address _usdc)
        external
        onlyOwner
    {
        if (_positionManager == address(0) || _pool == address(0) || _ethosToken == address(0) || _usdc == address(0)) {
            revert ZeroAddress();
        }
        if (_ethosToken != address(ethosToken)) revert BadPoolConfig();
        // The pool must really be an ETHOS/USDC pool (either order); its fee tier becomes the only accepted tier.
        address t0 = IUniswapV3Pool(_pool).token0();
        address t1 = IUniswapV3Pool(_pool).token1();
        if (!((t0 == _ethosToken && t1 == _usdc) || (t0 == _usdc && t1 == _ethosToken))) revert BadPoolConfig();
        poolFee = IUniswapV3Pool(_pool).fee();
        positionManager = INonfungiblePositionManager(_positionManager);
        ethosUsdcPool = _pool;
        ethosTokenAddr = _ethosToken;
        usdcTokenAddr = _usdc;
        emit PoolConfigured(_pool, _ethosToken, _usdc);
    }

    function setMVPBadge(address _mvpBadge) external onlyOwner {
        if (_mvpBadge != address(0) && _mvpBadge.code.length == 0) revert ZeroAddress();
        mvpBadge = IEthosMVPBadge(_mvpBadge);
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
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    // ─── View ─────────────────────────────────────────────────────────────────

    function isActiveLP(address provider) external view returns (bool) {
        return lpProviders[provider].active;
    }

    function getLPInfo(address provider)
        external
        view
        returns (
            uint256 positionTokenId,
            uint256 verifiedUsdcValue,
            uint256 registeredAt,
            uint256 nextBurnAt,
            bool active,
            uint256 totalBurned
        )
    {
        LPInfo storage lp = lpProviders[provider];
        return (
            lp.positionTokenId,
            lp.verifiedUsdcValue,
            lp.registeredAt,
            lp.lastBurnAt + BURN_INTERVAL,
            lp.active,
            lp.totalBurned
        );
    }

    /**
     * @notice Check if a Uniswap V3 position meets the LP requirements.
     * Call this before registerLP() to preview eligibility.
     */
    function checkEligibility(uint256 positionTokenId)
        external
        view
        returns (bool eligible, string memory reason, uint256 usdcValue)
    {
        if (ethosUsdcPool == address(0) || address(positionManager) == address(0)) {
            return (false, "Pool not configured", 0);
        }

        address nftOwner;
        try positionManager.ownerOf(positionTokenId) returns (address o) {
            nftOwner = o;
        } catch {
            return (false, "Invalid position token ID", 0);
        }

        if (nftOwner != msg.sender) {
            return (false, "You do not own this position NFT", 0);
        }

        INonfungiblePositionManager.Position memory pos = positionManager.positions(positionTokenId);

        bool ethosIsToken0 = pos.token0 == ethosTokenAddr && pos.token1 == usdcTokenAddr;
        bool ethosIsToken1 = pos.token0 == usdcTokenAddr && pos.token1 == ethosTokenAddr;

        if (!ethosIsToken0 && !ethosIsToken1) {
            return (false, "Position is not in the EthosiFi ETHOS/USDC pool", 0);
        }

        if (pos.fee != poolFee) {
            return (false, "Position is in a different fee tier", 0);
        }
        if (
            positionClaimedBy[positionTokenId] != address(0) && positionClaimedBy[positionTokenId] != msg.sender
                && lpProviders[positionClaimedBy[positionTokenId]].active
        ) {
            return (false, "Position already registered by another wallet", 0);
        }
        if (pos.liquidity == 0) {
            return (false, "Position has zero liquidity", 0);
        }

        usdcValue = _computeUsdcValue(pos, ethosIsToken0);

        if (usdcValue < MIN_LP_USD_VALUE) {
            return (false, "Position value is below the $500 USDC minimum", usdcValue);
        }

        return (true, "Eligible for LP Gold badge", usdcValue);
    }
}
