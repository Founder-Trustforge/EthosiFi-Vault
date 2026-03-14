// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

/**
 * @title EthosToken
 * @notice $ETHOS — Native utility token of the EthosiFi Vault protocol
 * @dev ERC-20 with native burn mechanic. Fixed 100M supply. No inflation ever.
 *
 * Burn Mechanic:
 * - Pro subscription: 100 $ETHOS burned per month
 * - MVP stake: 100 $ETHOS burned per month from rewards
 * - LP Provider: 100 $ETHOS burned per month
 * - Every burn permanently reduces total supply
 *
 * EthosiFi Vault — The Unstealable Wallet
contract EthosToken {

    // ─── ERC-20 STATE ───────────────────────────────────────────────────────

    string public constant name     = "EthosiFi Token";
    string public constant symbol   = "$ETHOS";
    uint8  public constant decimals = 18;

    uint256 public constant TOTAL_SUPPLY = 100_000_000 * 1e18;
    uint256 public totalSupply;
    uint256 public totalBurned;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // ─── ALLOCATION CONSTANTS ────────────────────────────────────────────────

    uint256 public constant REWARDS_POOL_ALLOC    = 40_000_000 * 1e18; // 40%
    uint256 public constant TREASURY_ALLOC        = 20_000_000 * 1e18; // 20%
    uint256 public constant TEAM_ALLOC            = 20_000_000 * 1e18; // 20%
    uint256 public constant ECOSYSTEM_ALLOC       = 10_000_000 * 1e18; // 10%
    uint256 public constant EARLY_CONTRIBUTOR_ALLOC = 5_000_000 * 1e18; // 5%
    uint256 public constant PUBLIC_LAUNCH_ALLOC   =  5_000_000 * 1e18; // 5%

    // Burn rate per subscription period (100 $ETHOS)
    uint256 public constant SUBSCRIPTION_BURN = 100 * 1e18;

    // ─── ACCESS CONTROL ──────────────────────────────────────────────────────

    address public owner;
    address public stakingContract;
    address public paymasterContract;
    address public liquidityManager;

    // Authorized burners (staking, paymaster, liquidity contracts)
    mapping(address => bool) public authorizedBurners;

    // ─── VESTING ─────────────────────────────────────────────────────────────

    address public teamVestingContract;
    uint256 public teamTGEUnlocked; // 10M at TGE
    bool    public tgeExecuted;

    // ─── EVENTS ──────────────────────────────────────────────────────────────

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Burn(address indexed burner, address indexed from, uint256 amount, uint256 newTotalSupply);
    event BurnerAuthorized(address indexed burner);
    event BurnerRevoked(address indexed burner);
    event TGEExecuted(uint256 timestamp);

    // ─── ERRORS ──────────────────────────────────────────────────────────────

    error NotOwner();
    error NotAuthorizedBurner();
    error InsufficientBalance();
    error InsufficientAllowance();
    error TGEAlreadyExecuted();
    error ZeroAddress();
    error ZeroAmount();
    }

    // ─── CONSTRUCTOR ─────────────────────────────────────────────────────────

    constructor(
        address _treasury,
        address _ecosystem,
        address _earlyContributors,
        address _publicLaunch,
        address _teamVesting
    ) {
        owner = msg.sender;
        totalSupply = TOTAL_SUPPLY;

        // Mint allocations
        // Rewards pool stays in contract, distributed as non-transferable credits
        balanceOf[address(this)] = REWARDS_POOL_ALLOC;
        emit Transfer(address(0), address(this), REWARDS_POOL_ALLOC);

        // Treasury
        balanceOf[_treasury] = TREASURY_ALLOC;
        emit Transfer(address(0), _treasury, TREASURY_ALLOC);

        // Ecosystem growth
        balanceOf[_ecosystem] = ECOSYSTEM_ALLOC;
        emit Transfer(address(0), _ecosystem, ECOSYSTEM_ALLOC);

        // Early contributors — fully unlocked at TGE
        balanceOf[_earlyContributors] = EARLY_CONTRIBUTOR_ALLOC;
        emit Transfer(address(0), _earlyContributors, EARLY_CONTRIBUTOR_ALLOC);

        // Public launch — fully unlocked at TGE
        balanceOf[_publicLaunch] = PUBLIC_LAUNCH_ALLOC;
        emit Transfer(address(0), _publicLaunch, PUBLIC_LAUNCH_ALLOC);

        // Team: 10M to vesting contract now, 10M at TGE
        teamVestingContract = _teamVesting;
        balanceOf[_teamVesting] = TEAM_ALLOC / 2; // 10M to vesting
        emit Transfer(address(0), _teamVesting, TEAM_ALLOC / 2);

        // 10M held in contract for TGE unlock
        balanceOf[address(this)] += TEAM_ALLOC / 2;
        emit Transfer(address(0), address(this), TEAM_ALLOC / 2);
    }

    // ─── ERC-20 FUNCTIONS ────────────────────────────────────────────────────

    function transfer(address to, uint256 amount) external returns (bool) {
        if (to == address(0)) revert ZeroAddress();
        if (balanceOf[msg.sender] < amount) revert InsufficientBalance();
    }
        unchecked{
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
        
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (to == address(0)) revert ZeroAddress();
        if (balanceOf[from] < amount) revert InsufficientBalance();
        if (allowance[from][msg.sender] < amount) revert InsufficientAllowance();
    }
        unchecked {
            balanceOf[from] -= amount;
            allowance[from][msg.sender] -= amount;
            balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    // ─── BURN FUNCTIONS ──────────────────────────────────────────────────────

    /**
     * @notice Burn tokens from a user's account (called by authorized contracts)
     * @dev Only staking, paymaster, and liquidity contracts can burn
     * @param from Address to burn from
     * @param amount Amount to burn
     */
    function burnFrom(address from, uint256 amount) external {
        if (!authorizedBurners[msg.sender]) revert NotAuthorizedBurner();
        if (amount == 0) revert ZeroAmount();
        if (balanceOf[from] < amount) revert InsufficientBalance();
    }
        unchecked {
            balanceOf[from] -= amount;
            totalSupply -= amount;
            totalBurned += amount;
        emit Transfer(from, address(0), amount);
        emit Burn(msg.sender, from, amount, totalSupply);
    }

    /**
     * @notice Burn your own tokens
     */
    function burn(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        if (balanceOf[msg.sender] < amount) revert InsufficientBalance();
    }
        unchecked {
            balanceOf[msg.sender] -= amount;
            totalSupply -= amount;
            totalBurned += amount;

        emit Transfer(msg.sender, address(0), amount);
        emit Burn(msg.sender, msg.sender, amount, totalSupply);
    }

    /**
     * @notice Burn subscription fee — exactly SUBSCRIPTION_BURN (100 $ETHOS)
     * @dev Convenience function called by paymaster for subscription payments
     */
    function burnSubscriptionFee(address subscriber) external {
        if (!authorizedBurners[msg.sender]) revert NotAuthorizedBurner();
        if (balanceOf[subscriber] < SUBSCRIPTION_BURN) revert InsufficientBalance();
    }
        unchecked {
            balanceOf[subscriber] -= SUBSCRIPTION_BURN;
            totalSupply -= SUBSCRIPTION_BURN;
            totalBurned += SUBSCRIPTION_BURN;

        emit Transfer(subscriber, address(0), SUBSCRIPTION_BURN);
        emit Burn(msg.sender, subscriber, SUBSCRIPTION_BURN, totalSupply);
    }

    // ─── OWNER FUNCTIONS ─────────────────────────────────────────────────────

    function authorizeBurner(address burner) external {
        if (msg.sender != owner) revert NotOwner();
        if (burner == address(0)) revert ZeroAddress();
        authorizedBurners[burner] = true;
        emit BurnerAuthorized(burner);
    }

    function revokeBurner(address burner) external {
        if (msg.sender != owner) revert NotOwner();
        authorizedBurners[burner] = false;
        emit BurnerRevoked(burner);
    }

    function setContracts(
        address _staking,
        address _paymaster,
        address _liquidityManager
    ) external {
        if (msg.sender != owner) revert NotOwner();
        stakingContract = _staking;
        paymasterContract = _paymaster;
        liquidityManager = _liquidityManager;
        authorizedBurners[_staking] = true;
        authorizedBurners[_paymaster] = true;
        authorizedBurners[_liquidityManager] = true;
    }

    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert NotOwner();
        if (newOwner == address(0)) revert ZeroAddress();
        owner = newOwner;
    }

    // ─── VIEW FUNCTIONS ──────────────────────────────────────────────────────

    function circulatingSupply() external view returns (uint256) {
        return totalSupply - balanceOf[address(this)];
    }

    function burnProgress() external view returns (uint256 burned, uint256 percentBurned) {
        burned = totalBurned;
        percentBurned = (totalBurned * 100) / TOTAL_SUPPLY;
    }
