// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {IModule} from "erc7579/interfaces/IERC7579Module.sol";
import {CallDecoder} from "./lib/CallDecoder.sol";
import {RouterGated} from "./lib/RouterGated.sol";

/**
 * @title SeniorModeGuard
 * @notice EthosiFi Vault - hardened profile for elderly / non-technical users (Pillar 6).
 *
 * This is a POLICY HOOK (a sub-hook of the account's EthosiHookRouter), not a validator: it never
 * authorizes anything, it can only REFUSE. (The previous version was installed as a validator and
 * returned "valid" without checking any signature, which would have let anyone spend.)
 *
 * While active it restricts EVERY outgoing call from the account, whoever signed it:
 *  - only inside the allowed hours of day (in the account's UTC offset);
 *  - transfers only of tokens that have limits configured, <= per-tx limit, <= daily limit;
 *  - recipients (and any non-transfer call target) must be on the guardian-approved list;
 *  - raising a limit is queued for GUARDIAN_RESPONSE_WINDOW so another guardian / the user can
 *    object; lowering is immediate.
 */
contract SeniorModeGuard is IModule, RouterGated {
    uint256 public constant GUARDIAN_RESPONSE_WINDOW = 24 hours;
    uint256 public constant MAX_GUARDIANS = 10;

    struct TokenLimit {
        address token;
        uint128 txLimit;
        uint128 dailyLimit;
    }

    struct Limit {
        bool set;
        uint128 txLimit;
        uint128 dailyLimit;
    }

    struct PendingLimit {
        uint128 txLimit;
        uint128 dailyLimit;
        uint256 applyAfter;
    }

    struct Config {
        bool initialized;
        bool active;
        bool requireApproved; // recipients must be approved (transfer recipients, call targets)
        int32 utcOffsetSeconds;
        uint8 startHour; // local hour, inclusive
        uint8 endHour; // local hour, exclusive (<= 24)
        address[] guardians;
    }

    struct Day {
        uint64 day;
        uint192 spent;
    }

    mapping(address => Config) private _cfg;
    mapping(address => mapping(address => bool)) private _isGuardian;
    mapping(address => mapping(address => bool)) public approved; // account => recipient/target
    mapping(address => mapping(address => Limit)) public limits; // account => token
    mapping(address => mapping(address => PendingLimit)) public pendingLimits;
    mapping(address => mapping(address => Day)) public daily; // account => token

    event SeniorModeActivated(address indexed account);
    event AddressApproved(address indexed account, address indexed recipient, address by);
    event AddressRevoked(address indexed account, address indexed recipient, address by);
    event LimitChanged(address indexed account, address indexed token, uint256 txLimit, uint256 dailyLimit);
    event LimitIncreaseQueued(
        address indexed account, address indexed token, uint256 txLimit, uint256 dailyLimit, uint256 applyAfter
    );
    event LimitIncreaseCancelled(address indexed account, address indexed token, address by);
    event HoursChanged(address indexed account, uint8 startHour, uint8 endHour, int32 utcOffsetSeconds);

    error OutsideAllowedHours();
    error RecipientNotApproved(address recipient);
    error TokenNotAllowed(address token);
    error TxLimitExceeded(address token, uint256 amount);
    error DailyLimitExceeded(address token, uint256 amount);
    error NotGuardian();
    error NotAuthorized();

    constructor(address router_) RouterGated(router_) {}

    // ─── Module lifecycle (msg.sender = account) ──────────────────────────────

    /// @param data abi.encode(address[] guardians, int32 utcOffsetSeconds, uint8 startHour, uint8 endHour,
    ///   bool requireApproved, address[] approvedAtInstall, TokenLimit[] tokenLimits)
    function onInstall(bytes calldata data) external override {
        Config storage c = _cfg[msg.sender];
        if (c.initialized) revert AlreadyInitialized(msg.sender);

        (
            address[] memory guardians,
            int32 offset,
            uint8 startHour,
            uint8 endHour,
            bool requireApproved,
            address[] memory approvedList,
            TokenLimit[] memory tl
        ) = abi.decode(data, (address[], int32, uint8, uint8, bool, address[], TokenLimit[]));

        require(guardians.length > 0 && guardians.length <= MAX_GUARDIANS, "Guardians 1..10");
        require(startHour < endHour && endHour <= 24, "Invalid hours");
        require(offset >= -12 hours && offset <= 14 hours, "Invalid offset");

        c.initialized = true;
        c.active = true;
        c.requireApproved = requireApproved;
        c.utcOffsetSeconds = offset;
        c.startHour = startHour;
        c.endHour = endHour;
        for (uint256 i; i < guardians.length; i++) {
            require(guardians[i] != address(0) && !_isGuardian[msg.sender][guardians[i]], "Bad guardian");
            c.guardians.push(guardians[i]);
            _isGuardian[msg.sender][guardians[i]] = true;
        }
        for (uint256 i; i < approvedList.length; i++) {
            approved[msg.sender][approvedList[i]] = true;
        }
        for (uint256 i; i < tl.length; i++) {
            limits[msg.sender][tl[i].token] = Limit(true, tl[i].txLimit, tl[i].dailyLimit);
        }
        emit SeniorModeActivated(msg.sender);
    }

    function onUninstall(bytes calldata) external override {
        Config storage c = _cfg[msg.sender];
        for (uint256 i; i < c.guardians.length; i++) {
            delete _isGuardian[msg.sender][c.guardians[i]];
        }
        delete _cfg[msg.sender];
    }

    function isModuleType(uint256) external pure override returns (bool) {
        return false; // sub-hook of the router; not installed directly on accounts
    }

    function isInitialized(address account) external view override returns (bool) {
        return _cfg[account].initialized;
    }

    // ─── Sub-hook ─────────────────────────────────────────────────────────────

    function preCheck(address account, address target, uint256 value, bytes memory callData)
        external
        onlyRouter
        returns (bytes memory)
    {
        Config storage c = _cfg[account];
        if (!c.active) return "";

        // time-of-day (account-local)
        uint256 local = uint256(int256(block.timestamp) + int256(c.utcOffsetSeconds));
        uint256 hourOfDay = (local % 1 days) / 1 hours;
        if (hourOfDay < c.startHour || hourOfDay >= c.endHour) revert OutsideAllowedHours();

        if (target == account) return ""; // account self-management (guarded by the other hooks)

        CallDecoder.Transfer memory t = CallDecoder.classifyMem(target, value, callData);
        if (t.kind == 0) {
            // arbitrary contract call: only to guardian-approved targets
            if (!approved[account][target]) revert RecipientNotApproved(target);
            return "";
        }

        if (c.requireApproved && !approved[account][t.recipient]) revert RecipientNotApproved(t.recipient);

        Limit memory l = limits[account][t.token];
        if (!l.set) revert TokenNotAllowed(t.token);
        if (t.amount > l.txLimit) revert TxLimitExceeded(t.token, t.amount);

        Day storage d = daily[account][t.token];
        uint64 today = uint64(local / 1 days);
        uint256 spent = d.day == today ? d.spent : 0;
        if (spent + t.amount > l.dailyLimit) revert DailyLimitExceeded(t.token, t.amount);
        d.day = today;
        d.spent = uint192(spent + t.amount); // <= dailyLimit <= uint128.max
        return "";
    }

    function postCheck(bytes calldata) external pure {}

    // ─── Guardian controls ────────────────────────────────────────────────────

    modifier onlyGuardian(address account) {
        if (!_isGuardian[account][msg.sender]) revert NotGuardian();
        _;
    }

    function approveAddress(address account, address recipient) external onlyGuardian(account) {
        approved[account][recipient] = true;
        emit AddressApproved(account, recipient, msg.sender);
    }

    /// @notice Guardian or the account itself may revoke an approval (revoking only tightens).
    function revokeAddress(address account, address recipient) external {
        if (msg.sender != account && !_isGuardian[account][msg.sender]) revert NotAuthorized();
        approved[account][recipient] = false;
        emit AddressRevoked(account, recipient, msg.sender);
    }

    /// @notice Set a token's limits. Lowering is immediate; any increase is queued.
    function setLimit(address account, address token, uint128 txLimit, uint128 dailyLimit)
        external
        onlyGuardian(account)
    {
        Limit memory cur = limits[account][token];
        if (cur.set && txLimit <= cur.txLimit && dailyLimit <= cur.dailyLimit) {
            limits[account][token] = Limit(true, txLimit, dailyLimit);
            delete pendingLimits[account][token];
            emit LimitChanged(account, token, txLimit, dailyLimit);
        } else {
            uint256 at = block.timestamp + GUARDIAN_RESPONSE_WINDOW;
            pendingLimits[account][token] = PendingLimit(txLimit, dailyLimit, at);
            emit LimitIncreaseQueued(account, token, txLimit, dailyLimit, at);
        }
    }

    function applyLimit(address account, address token) external {
        PendingLimit memory p = pendingLimits[account][token];
        require(p.applyAfter != 0 && block.timestamp >= p.applyAfter, "Not ready");
        delete pendingLimits[account][token];
        limits[account][token] = Limit(true, p.txLimit, p.dailyLimit);
        emit LimitChanged(account, token, p.txLimit, p.dailyLimit);
    }

    function cancelLimit(address account, address token) external {
        if (msg.sender != account && !_isGuardian[account][msg.sender]) revert NotAuthorized();
        require(pendingLimits[account][token].applyAfter != 0, "Nothing queued");
        delete pendingLimits[account][token];
        emit LimitIncreaseCancelled(account, token, msg.sender);
    }

    function setAllowedHours(address account, uint8 startHour, uint8 endHour) external onlyGuardian(account) {
        require(startHour < endHour && endHour <= 24, "Invalid hours");
        // narrowing the window is immediate; widening is also guardian-only (guardians are trusted)
        _cfg[account].startHour = startHour;
        _cfg[account].endHour = endHour;
        emit HoursChanged(account, startHour, endHour, _cfg[account].utcOffsetSeconds);
    }

    // ─── Views ────────────────────────────────────────────────────────────────

    function getConfig(address account)
        external
        view
        returns (bool active, bool requireApproved, uint8 startHour, uint8 endHour, int32 utcOffsetSeconds)
    {
        Config storage c = _cfg[account];
        return (c.active, c.requireApproved, c.startHour, c.endHour, c.utcOffsetSeconds);
    }

    function remainingDaily(address account, address token) external view returns (uint256) {
        Limit memory l = limits[account][token];
        if (!l.set) return 0;
        uint256 local = uint256(int256(block.timestamp) + int256(_cfg[account].utcOffsetSeconds));
        Day memory d = daily[account][token];
        uint256 spent = d.day == uint64(local / 1 days) ? d.spent : 0;
        return l.dailyLimit > spent ? l.dailyLimit - spent : 0;
    }
}
