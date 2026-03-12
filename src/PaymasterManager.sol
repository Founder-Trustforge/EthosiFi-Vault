// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {IModule} from "erc7579/interfaces/IModule.sol";

/**
 * @title PaymasterManager
 * @notice EthosiFi Vault — Gasless transactions. Pay fees in USDC. Never hold ETH.
 * @dev Implements ERC-4337 paymaster logic.
 *      The single biggest onboarding barrier in all of Web3 is:
 *      "I need ETH to send tokens." This contract eliminates that.
 *
 *      Users pay gas fees in USDC (or other supported stablecoins).
 *      EthosiFi's paymaster pool sponsors the ETH gas on their behalf,
 *      then deducts the USDC equivalent from the user's vault.
 *
 *      Fee tiers:
 *      - Free tier: Up to 10 sponsored transactions/month
 *      - Pro tier: Unlimited sponsored transactions
 *      - Enterprise: Custom fee arrangements
 *
 *      Supported fee tokens: USDC, DAI, USDT, WETH
 *
 * Layer: UX & Accessibility (Pillar 7)
 */
contract PaymasterManager is IModule {

    uint256 constant MODULE_TYPE_HOOK = 4;

    // ERC-4337 paymaster validation return values
    uint256 constant PAYMASTER_VALIDATION_SUCCESS = 0;
    uint256 constant PAYMASTER_VALIDATION_FAILED  = 1;

    // Supported stablecoins (set at deployment)
    address public USDC;
    address public DAI;
    address public USDT;
    address public WETH;

    // Pimlico / Alchemy paymaster integration endpoint
    address public paymasterEntryPoint;

    uint256 public constant FREE_MONTHLY_TX = 10;
    uint256 public constant GAS_OVERHEAD    = 50_000;  // Estimated gas overhead per sponsored tx

    enum UserTier { FREE, PRO, FAMILY, ENTERPRISE }

    struct PaymasterConfig {
        bool        initialized;
        UserTier    tier;
        address     feeToken;        // Which token user pays fees in
        uint256     feeBalance;      // Pre-deposited fee token balance
        uint256     monthlyTxCount;
        uint256     currentMonth;    // block.timestamp / 30 days
        uint256     lifetimeTxCount;
        bool        active;
    }

    struct FeeToken {
        address tokenAddress;
        uint256 exchangeRate;   // Token per 1 gwei of gas (scaled by 1e18)
        bool    supported;
        string  symbol;
    }

    struct SponsoredTx {
        bytes32  txHash;
        uint256  gasUsed;
        uint256  feePaid;
        address  feeToken;
        uint256  timestamp;
    }

    mapping(address => PaymasterConfig) public configs;
    mapping(address => FeeToken) public feeTokens;
    mapping(address => SponsoredTx[]) public txHistory;
    mapping(address => uint256) public paymasterPool; // ETH pool per fee token

    address[] public supportedTokenList;

    event TransactionSponsored(address indexed account, bytes32 txHash, uint256 gasUsed, uint256 feePaid, address feeToken);
    event FeeDeposited(address indexed account, address feeToken, uint256 amount);
    event FeeWithdrawn(address indexed account, address feeToken, uint256 amount);
    event TierUpgraded(address indexed account, UserTier newTier);
    event FreeQuotaExhausted(address indexed account, uint256 month);
    event PaymasterPoolDeposited(address indexed token, uint256 ethAmount);

    // ─────────────────────────────────────────────
    // Module Lifecycle
    // ─────────────────────────────────────────────

    function onInstall(bytes calldata data) external override {
        require(!configs[msg.sender].initialized, "Already initialized");

        (uint8 tier, address feeToken) = abi.decode(data, (uint8, address));

        require(tier <= uint8(UserTier.ENTERPRISE), "Invalid tier");

        address resolvedFeeToken = feeToken;
        if (resolvedFeeToken == address(0)) resolvedFeeToken = USDC;

        configs[msg.sender] = PaymasterConfig({
            initialized:     true,
            tier:            UserTier(tier),
            feeToken:        resolvedFeeToken,
            feeBalance:      0,
            monthlyTxCount:  0,
            currentMonth:    block.timestamp / 30 days,
            lifetimeTxCount: 0,
            active:          true
        });
    }

    function onUninstall(bytes calldata) external override {
        PaymasterConfig storage config = configs[msg.sender];
        // Return any remaining fee balance
        if (config.feeBalance > 0) {
            _transferToken(config.feeToken, msg.sender, config.feeBalance);
        }
        delete configs[msg.sender];
    }

    // ─────────────────────────────────────────────
    // ERC-4337 Paymaster Validation
    // ─────────────────────────────────────────────

    /**
     * @notice Validates that EthosiFi will sponsor this user operation.
     * @dev Called by the EntryPoint before execution.
     *      Returns 0 (success) if EthosiFi will pay gas. Reverts if not.
     */
    function validatePaymasterUserOp(
        address account,
        uint256 maxGasCost
    ) external returns (uint256) {
        PaymasterConfig storage config = configs[account];
        require(config.initialized && config.active, "Paymaster not configured");

        _refreshMonthlyQuota(config);

        // Pro, Family, Enterprise: unlimited sponsoring (deduct from fee balance)
        if (config.tier != UserTier.FREE) {
            uint256 fee = _calculateFee(config.feeToken, maxGasCost);
            require(config.feeBalance >= fee, "Insufficient fee balance. Top up your USDC balance.");
            config.feeBalance -= fee;
            return PAYMASTER_VALIDATION_SUCCESS;
        }

        // Free tier: check monthly quota
        if (config.monthlyTxCount >= FREE_MONTHLY_TX) {
            emit FreeQuotaExhausted(account, config.currentMonth);
            revert("EthosiFi: Free tier limit (10 tx/month) reached. Upgrade to Pro for unlimited gasless transactions.");
        }

        config.monthlyTxCount++;
        return PAYMASTER_VALIDATION_SUCCESS;
    }

    /**
     * @notice Post-execution: record actual gas used and finalize fee.
     */
    function postOp(
        address account,
        bytes32 txHash,
        uint256 gasUsed
    ) external {
        PaymasterConfig storage config = configs[account];
        if (!config.initialized) return;

        uint256 feePaid = config.tier == UserTier.FREE ? 0 : _calculateFee(config.feeToken, gasUsed);

        config.lifetimeTxCount++;

        txHistory[account].push(SponsoredTx({
            txHash:    txHash,
            gasUsed:   gasUsed,
            feePaid:   feePaid,
            feeToken:  config.feeToken,
            timestamp: block.timestamp
        }));

        emit TransactionSponsored(account, txHash, gasUsed, feePaid, config.feeToken);
    }

    // ─────────────────────────────────────────────
    // User: Deposit Fee Tokens
    // ─────────────────────────────────────────────

    /**
     * @notice Deposit USDC (or other supported token) to pre-fund gas fees.
     * @dev Users never need ETH. They top up USDC and EthosiFi handles the rest.
     */
    function depositFeeToken(address feeToken, uint256 amount) external {
        require(feeTokens[feeToken].supported, "Token not supported");
        require(amount > 0, "Zero amount");

        // Transfer token from user to this contract
        _transferFromToken(feeToken, msg.sender, address(this), amount);

        configs[msg.sender].feeBalance += amount;
        configs[msg.sender].feeToken    = feeToken;

        emit FeeDeposited(msg.sender, feeToken, amount);
    }

    function withdrawFeeToken(uint256 amount) external {
        PaymasterConfig storage config = configs[msg.sender];
        require(config.feeBalance >= amount, "Insufficient balance");
        config.feeBalance -= amount;
        _transferToken(config.feeToken, msg.sender, amount);
        emit FeeWithdrawn(msg.sender, config.feeToken, amount);
    }

    // ─────────────────────────────────────────────
    // Admin: Manage Fee Tokens & Pool
    // ─────────────────────────────────────────────

    function addFeeToken(address token, uint256 exchangeRate, string calldata symbol) external {
        // Production: onlyOwner
        feeTokens[token] = FeeToken({
            tokenAddress:  token,
            exchangeRate:  exchangeRate,
            supported:     true,
            symbol:        symbol
        });
        supportedTokenList.push(token);
    }

    function upgradeTier(address account, uint8 newTier) external {
        // Production: called by subscription contract after payment verification
        require(newTier <= uint8(UserTier.ENTERPRISE), "Invalid tier");
        configs[account].tier = UserTier(newTier);
        emit TierUpgraded(account, UserTier(newTier));
    }

    function depositToPool(address feeToken) external payable {
        // Production: EthosiFi treasury funds the paymaster pool
        paymasterPool[feeToken] += msg.value;
        emit PaymasterPoolDeposited(feeToken, msg.value);
    }

    // ─────────────────────────────────────────────
    // Internal Helpers
    // ─────────────────────────────────────────────

    function _refreshMonthlyQuota(PaymasterConfig storage config) internal {
        uint256 thisMonth = block.timestamp / 30 days;
        if (config.currentMonth < thisMonth) {
            config.currentMonth   = thisMonth;
            config.monthlyTxCount = 0;
        }
    }

    function _calculateFee(address feeToken, uint256 gasAmount) internal view returns (uint256) {
        FeeToken storage token = feeTokens[feeToken];
        if (!token.supported) return 0;
        // fee = gasAmount * gasPrice * exchangeRate / 1e18
        return (gasAmount * GAS_OVERHEAD * token.exchangeRate) / 1e18;
    }

    function _transferToken(address token, address to, uint256 amount) internal {
        // Production: call ERC20 transfer
        (bool success, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        require(success, "Token transfer failed");
    }

    function _transferFromToken(address token, address from, address to, uint256 amount) internal {
        (bool success, ) = token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, amount));
        require(success, "Token transferFrom failed");
    }

    // ─────────────────────────────────────────────
    // View Helpers
    // ─────────────────────────────────────────────

    function getConfig(address account) external view returns (
        UserTier tier, address feeToken, uint256 feeBalance, uint256 monthlyTxCount, uint256 lifetimeTxCount
    ) {
        PaymasterConfig storage c = configs[account];
        return (c.tier, c.feeToken, c.feeBalance, c.monthlyTxCount, c.lifetimeTxCount);
    }

    function getRemainingFreeQuota(address account) external view returns (uint256) {
        PaymasterConfig storage c = configs[account];
        if (c.tier != UserTier.FREE) return type(uint256).max;
        uint256 used = c.monthlyTxCount;
        return FREE_MONTHLY_TX > used ? FREE_MONTHLY_TX - used : 0;
    }

    function getSupportedTokens() external view returns (address[] memory) {
        return supportedTokenList;
    }

    function preCheck(address, address, uint256, bytes calldata) external pure returns (bytes memory) { return ""; }
    function postCheck(bytes calldata) external pure {}

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function isInitialized(address account) external view override returns (bool) {
        return configs[account].initialized;
    }
}
