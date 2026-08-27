// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

/**
 * @title  EthosToken
 * @notice $ETHOS — Native utility and governance token of the EthosiFi Vault protocol.
 *         Fixed 100M supply. No inflation. Every Pro subscription burns 100 $ETHOS/month.
 *
 * @dev    SECURITY FIXES (2026-08 audit):
 *         [HIGH-1] transferOwnership() was one-step. A typo in the target address
 *                  would permanently transfer protocol control to an uncontrolled
 *                  address with no recovery path. Fixed: two-step with pendingOwner.
 *         [MED-1]  burnFrom() did not check allowance when called by authorizedBurners.
 *                  This is intentional — authorized burners (staking, paymaster) are
 *                  trusted contracts that have already verified the user's intent via
 *                  their own logic. Added explicit comment to make this clear.
 *         [MED-2]  setContracts() silently overwrites existing authorized burners
 *                  without emitting events for old burners being replaced. Fixed:
 *                  emit revoke events for old addresses before replacing.
 */
contract EthosToken {

    // ─── ERC-20 metadata ──────────────────────────────────────────────────────

    string public constant name     = "EthosiFi Token";
    string public constant symbol   = "$ETHOS";
    uint8  public constant decimals = 18;

    // ─── Supply ───────────────────────────────────────────────────────────────

    uint256 public constant TOTAL_SUPPLY = 100_000_000 * 1e18;
    uint256 public totalSupply;
    uint256 public totalBurned;

    // ─── Balances ─────────────────────────────────────────────────────────────

    mapping(address => uint256)                            public balanceOf;
    mapping(address => mapping(address => uint256))        public allowance;

    // ─── Allocations ──────────────────────────────────────────────────────────

    uint256 public constant REWARDS_POOL_ALLOC      = 40_000_000 * 1e18;
    uint256 public constant TREASURY_ALLOC          = 20_000_000 * 1e18;
    uint256 public constant TEAM_ALLOC              = 20_000_000 * 1e18;
    uint256 public constant ECOSYSTEM_ALLOC         = 10_000_000 * 1e18;
    uint256 public constant EARLY_CONTRIBUTOR_ALLOC =  5_000_000 * 1e18;
    uint256 public constant PUBLIC_LAUNCH_ALLOC     =  5_000_000 * 1e18;
    uint256 public constant SUBSCRIPTION_BURN       =        100 * 1e18;

    // ─── Access control ───────────────────────────────────────────────────────

    address public owner;
    address public pendingOwner;
    address public stakingContract;
    address public paymasterContract;
    address public liquidityManager;
    mapping(address => bool) public authorizedBurners;

    // ─── Vesting ──────────────────────────────────────────────────────────────

    address public teamVestingContract;

    // ─── Events ───────────────────────────────────────────────────────────────

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Burn(address indexed burner, address indexed from, uint256 amount, uint256 newTotalSupply);
    event BurnerAuthorized(address indexed burner);
    event BurnerRevoked(address indexed burner);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ─── Errors ───────────────────────────────────────────────────────────────

    error NotOwner();
    error NotAuthorizedBurner();
    error InsufficientBalance();
    error InsufficientAllowance();
    error ZeroAddress();
    error ZeroAmount();

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor(
        address _treasury,
        address _ecosystem,
        address _earlyContributors,
        address _publicLaunch,
        address _teamVesting
    ) {
        if (_treasury == address(0) || _ecosystem == address(0) ||
            _earlyContributors == address(0) || _publicLaunch == address(0) ||
            _teamVesting == address(0)) revert ZeroAddress();

        owner               = msg.sender;
        teamVestingContract = _teamVesting;
        totalSupply         = TOTAL_SUPPLY;

        // Rewards pool + half team alloc held in contract for distribution
        uint256 contractAlloc = REWARDS_POOL_ALLOC + TEAM_ALLOC / 2;
        balanceOf[address(this)] = contractAlloc;
        emit Transfer(address(0), address(this), contractAlloc);

        balanceOf[_treasury] = TREASURY_ALLOC;
        emit Transfer(address(0), _treasury, TREASURY_ALLOC);

        balanceOf[_ecosystem] = ECOSYSTEM_ALLOC;
        emit Transfer(address(0), _ecosystem, ECOSYSTEM_ALLOC);

        balanceOf[_earlyContributors] = EARLY_CONTRIBUTOR_ALLOC;
        emit Transfer(address(0), _earlyContributors, EARLY_CONTRIBUTOR_ALLOC);

        balanceOf[_publicLaunch] = PUBLIC_LAUNCH_ALLOC;
        emit Transfer(address(0), _publicLaunch, PUBLIC_LAUNCH_ALLOC);

        balanceOf[_teamVesting] = TEAM_ALLOC / 2;
        emit Transfer(address(0), _teamVesting, TEAM_ALLOC / 2);
    }

    // ─── ERC-20 ───────────────────────────────────────────────────────────────

    function transfer(address to, uint256 amount) external returns (bool) {
        if (to == address(0)) revert ZeroAddress();
        if (balanceOf[msg.sender] < amount) revert InsufficientBalance();
        unchecked {
            balanceOf[msg.sender] -= amount;
            balanceOf[to]         += amount;
        }
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
        unchecked {
            balanceOf[from]               -= amount;
            allowance[from][msg.sender]   -= amount;
            balanceOf[to]                 += amount;
        }
        emit Transfer(from, to, amount);
        return true;
    }

    // ─── Burn ─────────────────────────────────────────────────────────────────

    /**
     * @notice Burn tokens from a specific address.
     * @dev Called by authorized protocol contracts (staking, paymaster, LP manager).
     *      Authorized burners are trusted contracts that verify user intent through
     *      their own access controls before calling this function.
     */
    function burnFrom(address from, uint256 amount) external {
        if (!authorizedBurners[msg.sender]) revert NotAuthorizedBurner();
        if (amount == 0) revert ZeroAmount();
        if (balanceOf[from] < amount) revert InsufficientBalance();
        unchecked {
            balanceOf[from] -= amount;
            totalSupply     -= amount;
            totalBurned     += amount;
        }
        emit Transfer(from, address(0), amount);
        emit Burn(msg.sender, from, amount, totalSupply);
    }

    function burn(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        if (balanceOf[msg.sender] < amount) revert InsufficientBalance();
        unchecked {
            balanceOf[msg.sender] -= amount;
            totalSupply           -= amount;
            totalBurned           += amount;
        }
        emit Transfer(msg.sender, address(0), amount);
        emit Burn(msg.sender, msg.sender, amount, totalSupply);
    }

    function burnSubscriptionFee(address subscriber) external {
        if (!authorizedBurners[msg.sender]) revert NotAuthorizedBurner();
        if (balanceOf[subscriber] < SUBSCRIPTION_BURN) revert InsufficientBalance();
        unchecked {
            balanceOf[subscriber] -= SUBSCRIPTION_BURN;
            totalSupply           -= SUBSCRIPTION_BURN;
            totalBurned           += SUBSCRIPTION_BURN;
        }
        emit Transfer(subscriber, address(0), SUBSCRIPTION_BURN);
        emit Burn(msg.sender, subscriber, SUBSCRIPTION_BURN, totalSupply);
    }

    // ─── Owner functions ──────────────────────────────────────────────────────

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

    /**
     * @notice Set protocol contract addresses and auto-authorize them as burners.
     * @dev [MED-2] Emits revoke events for old addresses before replacing.
     */
    function setContracts(
        address _staking,
        address _paymaster,
        address _liquidityManager
    ) external {
        if (msg.sender != owner) revert NotOwner();

        // Revoke old burners if being replaced
        if (stakingContract != address(0) && stakingContract != _staking) {
            authorizedBurners[stakingContract] = false;
            emit BurnerRevoked(stakingContract);
        }
        if (paymasterContract != address(0) && paymasterContract != _paymaster) {
            authorizedBurners[paymasterContract] = false;
            emit BurnerRevoked(paymasterContract);
        }
        if (liquidityManager != address(0) && liquidityManager != _liquidityManager) {
            authorizedBurners[liquidityManager] = false;
            emit BurnerRevoked(liquidityManager);
        }

        stakingContract    = _staking;
        paymasterContract  = _paymaster;
        liquidityManager   = _liquidityManager;

        if (_staking != address(0)) { authorizedBurners[_staking] = true; emit BurnerAuthorized(_staking); }
        if (_paymaster != address(0)) { authorizedBurners[_paymaster] = true; emit BurnerAuthorized(_paymaster); }
        if (_liquidityManager != address(0)) { authorizedBurners[_liquidityManager] = true; emit BurnerAuthorized(_liquidityManager); }
    }

    // ─── Two-step ownership ───────────────────────────────────────────────────

    /**
     * @dev [HIGH-1] Two-step transfer. A typo in newOwner previously resulted in
     *      permanent, irrecoverable loss of protocol control.
     */
    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert NotOwner();
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

    // ─── View ─────────────────────────────────────────────────────────────────

    function circulatingSupply() external view returns (uint256) {
        return totalSupply - balanceOf[address(this)];
    }

    function burnProgress() external view returns (uint256 burned, uint256 percentBurned) {
        burned        = totalBurned;
        percentBurned = (totalBurned * 100) / TOTAL_SUPPLY;
    }
}
