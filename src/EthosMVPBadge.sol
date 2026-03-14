// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

/**
 * @title EthosMVPBadge
 * @notice Soulbound ERC-721 NFT badge for EthosiFi Vault MVP members
 * @dev
 * - Non-transferable (soulbound) - tied permanently to vault address
 * - Tier 1: MVP (staker with 10,000+ $ETHOS)
 * - Tier 2: LP Provider (gold badge variant)
 * - Revocable by authorized contracts (staking, LP manager)
 * - On-chain proof of security tier
 *
 * EthosiFi Vault - The Unstealable Wallet
 */
contract EthosMVPBadge {

    // ─── STATE ───────────────────────────────────────────────────────────────

    string public constant name   = "EthosiFi MVP Badge";
    string public constant symbol = "ETHOS-MVP";

    address public owner;

    uint256 private _tokenIdCounter;

    // Tier definitions
    uint8 public constant TIER_MVP = 1; // Standard MVP - staker
    uint8 public constant TIER_LP  = 2; // Gold tier - LP provider

    struct Badge {
        uint8   tier;
        uint256 mintedAt;
        bool    active;
    }

    // tokenId => Badge
    mapping(uint256 => Badge) public badges;

    // address => tokenId (0 = no badge)
    mapping(address => uint256) public holderToken;

    // tokenId => owner address
    mapping(uint256 => address) public tokenOwner;

    // Authorized minters (staking contract, LP manager)
    mapping(address => bool) public authorizedMinters;

    // Total badges by tier
    mapping(uint8 => uint256) public totalByTier;
    uint256 public totalActive;

    // ─── EVENTS ──────────────────────────────────────────────────────────────

    // ERC-721 required
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    event BadgeMinted(address indexed to, uint256 indexed tokenId, uint8 tier, uint256 timestamp);
    event BadgeRevoked(address indexed from, uint256 indexed tokenId, uint8 tier);
    event BadgeUpgraded(address indexed holder, uint256 indexed tokenId, uint8 fromTier, uint8 toTier);
    event MinterAuthorized(address indexed minter);
    event MinterRevoked(address indexed minter);

    // ─── ERRORS ──────────────────────────────────────────────────────────────

    error NotOwner();
    error NotAuthorizedMinter();
    error AlreadyHasBadge();
    error NoBadge();
    error Soulbound();
    error InvalidTier();
    error ZeroAddress();

    // ─── CONSTRUCTOR ─────────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
        _tokenIdCounter = 1; // Start at 1
    }

    // ─── ERC-721 VIEW ────────────────────────────────────────────────────────

    function ownerOf(uint256 tokenId) external view returns (address) {
        return tokenOwner[tokenId];
    }

    function balanceOf(address account) external view returns (uint256) {
        return holderToken[account] != 0 && badges[holderToken[account]].active ? 1 : 0;
    }

    function tokenURI(uint256 tokenId) external view returns (string memory) {
        Badge memory badge = badges[tokenId];
        if (!badge.active) return "";

        // On-chain SVG metadata - no IPFS dependency
        if (badge.tier == TIER_LP) {
            return string(abi.encodePacked(
                'data:application/json;utf8,{"name":"EthosiFi LP Badge","description":"EthosiFi Vault LP Provider - Gold Tier MVP","image":"data:image/svg+xml;utf8,',
                _goldBadgeSVG(),
                '","attributes":[{"trait_type":"Tier","value":"LP Provider"},{"trait_type":"Status","value":"Active"}]}'
            ));
        }

        return string(abi.encodePacked(
            'data:application/json;utf8,{"name":"EthosiFi MVP Badge","description":"EthosiFi Vault MVP Member - Security Protocol Stakeholder","image":"data:image/svg+xml;utf8,',
            _mvpBadgeSVG(),
            '","attributes":[{"trait_type":"Tier","value":"MVP"},{"trait_type":"Status","value":"Active"}]}'
        ));
    }

    // ─── SOULBOUND: BLOCK TRANSFERS ──────────────────────────────────────────

    function transferFrom(address, address, uint256) external pure {
        revert Soulbound();
    }

    function safeTransferFrom(address, address, uint256) external pure {
        revert Soulbound();
    }

    function safeTransferFrom(address, address, uint256, bytes calldata) external pure {
        revert Soulbound();
    }

    function approve(address, uint256) external pure {
        revert Soulbound();
    }

    function setApprovalForAll(address, bool) external pure {
        revert Soulbound();
    }

    // ─── MINT & REVOKE ───────────────────────────────────────────────────────

    /**
     * @notice Mint a badge to an address
     * @param to Recipient address
     * @param tier Badge tier (1=MVP, 2=LP)
     */
    function mintBadge(address to, uint8 tier) external {
        if (!authorizedMinters[msg.sender]) revert NotAuthorizedMinter();
        if (to == address(0)) revert ZeroAddress();
        if (tier == 0 || tier > 2) revert InvalidTier();
        if (holderToken[to] != 0 && badges[holderToken[to]].active) revert AlreadyHasBadge();

        uint256 tokenId = _tokenIdCounter++;

        badges[tokenId] = Badge({
            tier: tier,
            mintedAt: block.timestamp,
            active: true
        });

        tokenOwner[tokenId] = to;
        holderToken[to] = tokenId;

        totalByTier[tier]++;
        totalActive++;

        emit Transfer(address(0), to, tokenId);
        emit BadgeMinted(to, tokenId, tier, block.timestamp);
    }

    /**
     * @notice Revoke a badge (called when user unstakes or removes LP)
     */
    function revokeBadge(address from) external {
        if (!authorizedMinters[msg.sender]) revert NotAuthorizedMinter();

        uint256 tokenId = holderToken[from];
        if (tokenId == 0 || !badges[tokenId].active) revert NoBadge();

        uint8 tier = badges[tokenId].tier;
        badges[tokenId].active = false;

        totalByTier[tier]--;
        totalActive--;

        emit Transfer(from, address(0), tokenId);
        emit BadgeRevoked(from, tokenId, tier);
    }

    /**
     * @notice Upgrade a badge from MVP to LP tier
     */
    function upgradeBadge(address holder) external {
        if (!authorizedMinters[msg.sender]) revert NotAuthorizedMinter();

        uint256 tokenId = holderToken[holder];
        if (tokenId == 0 || !badges[tokenId].active) revert NoBadge();
        if (badges[tokenId].tier == TIER_LP) return; // Already LP tier

        uint8 oldTier = badges[tokenId].tier;
        badges[tokenId].tier = TIER_LP;

        totalByTier[oldTier]--;
        totalByTier[TIER_LP]++;

        emit BadgeUpgraded(holder, tokenId, oldTier, TIER_LP);
    }

    // ─── VIEW FUNCTIONS ──────────────────────────────────────────────────────

    function hasBadge(address account) external view returns (bool) {
        uint256 tokenId = holderToken[account];
        return tokenId != 0 && badges[tokenId].active;
    }

    function getBadgeTier(address account) external view returns (uint8) {
        uint256 tokenId = holderToken[account];
        if (tokenId == 0 || !badges[tokenId].active) return 0;
        return badges[tokenId].tier;
    }

    function getTotalMVP() external view returns (uint256) {
        return totalByTier[TIER_MVP];
    }

    function getTotalLP() external view returns (uint256) {
        return totalByTier[TIER_LP];
    }

    // ─── SVG GENERATION ──────────────────────────────────────────────────────

    function _mvpBadgeSVG() internal pure returns (string memory) {
        return '<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 200 200%22><rect width=%22200%22 height=%22200%22 rx=%2220%22 fill=%22%231A1A2E%22/><circle cx=%22100%22 cy=%2270%22 r=%2240%22 fill=%22none%22 stroke=%220F3460%22 stroke-width=%223%22/><text x=%22100%22 y=%2278%22 text-anchor=%22middle%22 font-size=%2228%22 fill=%220F3460%22 font-family=%22Arial%22>E</text><text x=%22100%22 y=%22130%22 text-anchor=%22middle%22 font-size=%2214%22 fill=%22white%22 font-family=%22Arial%22>EthosiFi MVP</text><text x=%22100%22 y=%22150%22 text-anchor=%22middle%22 font-size=%2210%22 fill=%22666666%22 font-family=%22Arial%22>Vault Security Member</text></svg>';
    }

    function _goldBadgeSVG() internal pure returns (string memory) {
        return '<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 200 200%22><rect width=%22200%22 height=%22200%22 rx=%2220%22 fill=%22%231A1A2E%22/><circle cx=%22100%22 cy=%2270%22 r=%2240%22 fill=%22none%22 stroke=%22FFD700%22 stroke-width=%223%22/><text x=%22100%22 y=%2278%22 text-anchor=%22middle%22 font-size=%2228%22 fill=%22FFD700%22 font-family=%22Arial%22>E</text><text x=%22100%22 y=%22130%22 text-anchor=%22middle%22 font-size=%2214%22 fill=%22FFD700%22 font-family=%22Arial%22>EthosiFi LP Gold</text><text x=%22100%22 y=%22150%22 text-anchor=%22middle%22 font-size=%2210%22 fill=%22666666%22 font-family=%22Arial%22>Liquidity Provider</text></svg>';
    }

    // ─── OWNER FUNCTIONS ─────────────────────────────────────────────────────

    function authorizeMinter(address minter) external {
        if (msg.sender != owner) revert NotOwner();
        authorizedMinters[minter] = true;
        emit MinterAuthorized(minter);
    }

    function revokeMinter(address minter) external {
        if (msg.sender != owner) revert NotOwner();
        authorizedMinters[minter] = false;
        emit MinterRevoked(minter);
    }

    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert NotOwner();
        if (newOwner == address(0)) revert ZeroAddress();
        owner = newOwner;
    }
}
