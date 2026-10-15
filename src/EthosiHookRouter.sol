// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {IHook} from "erc7579/interfaces/IERC7579Module.sol";
import {Execution} from "erc7579/interfaces/IERC7579Account.sol";
import {ISubHook} from "./interfaces/ISubHook.sol";
import {CallDecoder} from "./lib/CallDecoder.sol";

/**
 * @title EthosiHookRouter
 * @notice An ERC-7579 account has exactly ONE hook slot. This is that hook: it fans every guarded
 * account call out to a per-account list of sub-hooks (AntiScamScreener, EmergencyFreeze,
 * MultiSigUpgradeGuard, ...), giving each the decoded (target, value, callData) of every inner call.
 *
 * Guarded entrypoints (those with `withHook` in MSAAdvanced): execute, executeFromExecutor,
 * installModule, uninstallModule.
 *  - execute / executeFromExecutor: single and batch modes are decoded and EACH inner call is
 *    checked. delegatecall / static / unknown call types REVERT (a vault has no business
 *    delegatecalling arbitrary code, and sub-hooks couldn't reason about it).
 *  - everything else (module management): sub-hooks get target = account, callData = full msg.data.
 *
 * Fail-closed: any decode failure reverts the whole call.
 */
contract EthosiHookRouter is IHook {
    uint256 internal constant MODULE_TYPE_HOOK = 4;
    uint256 public constant MAX_SUB_HOOKS = 10;
    bytes4 internal constant EXECUTE_FROM_EXECUTOR = 0xd691c964; // executeFromExecutor(bytes32,bytes)
    bytes4 internal constant INSTALL_MODULE = 0x9517e29f; // installModule(uint256,address,bytes)
    bytes4 internal constant UNINSTALL_MODULE = 0xa71763a8; // uninstallModule(uint256,address,bytes)

    mapping(address account => address[]) private _subs;
    mapping(address account => bool) private _initialized;

    error UnsupportedCallType(uint8 callType);
    error TooManySubHooks();
    error ZeroSubHook();
    error MalformedExecution();

    // ─── Module lifecycle (msg.sender = the account) ──────────────────────────

    function onInstall(bytes calldata data) external override {
        if (_initialized[msg.sender]) revert AlreadyInitialized(msg.sender);
        address[] memory subs = abi.decode(data, (address[]));
        if (subs.length > MAX_SUB_HOOKS) revert TooManySubHooks();
        for (uint256 i; i < subs.length; i++) {
            if (subs[i] == address(0)) revert ZeroSubHook();
            _subs[msg.sender].push(subs[i]);
        }
        _initialized[msg.sender] = true;
    }

    function onUninstall(bytes calldata) external override {
        delete _subs[msg.sender];
        _initialized[msg.sender] = false;
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return _initialized[smartAccount];
    }

    function subHooksOf(address account) external view returns (address[] memory) {
        return _subs[account];
    }

    // ─── Hook ─────────────────────────────────────────────────────────────────

    function preCheck(address, uint256 msgValue, bytes calldata msgData) external override returns (bytes memory) {
        address account = msg.sender; // hooks are invoked by the account itself
        address[] storage subs = _subs[account];
        if (subs.length == 0) return "";

        bytes4 sel = msgData.length >= 4 ? bytes4(msgData[:4]) : bytes4(0);
        if (sel == CallDecoder.EXECUTE || sel == EXECUTE_FROM_EXECUTOR) {
            (bytes32 mode, bytes memory ec) = abi.decode(msgData[4:], (bytes32, bytes));
            uint8 callType = uint8(bytes1(mode));
            if (callType == CallDecoder.CALLTYPE_SINGLE) {
                if (ec.length < 52) revert MalformedExecution();
                (address target, uint256 value, bytes memory data) = _decodeSingle(ec);
                _runInner(subs, account, target, value, data);
            } else if (callType == CallDecoder.CALLTYPE_BATCH) {
                Execution[] memory ex = abi.decode(ec, (Execution[]));
                for (uint256 i; i < ex.length; i++) {
                    _runInner(subs, account, ex[i].target, ex[i].value, ex[i].callData);
                }
            } else {
                revert UnsupportedCallType(callType);
            }
        } else {
            _runAll(subs, account, account, msgValue, msgData);
        }
        return "";
    }

    function postCheck(bytes calldata) external pure override {}

    // ─── Internals ────────────────────────────────────────────────────────────

    /// @dev An execute()-wrapped call to the account's own installModule/uninstallModule is NOT
    /// checked here: when it runs it re-enters the account through installModule/uninstallModule,
    /// which is itself hooked, so every sub-hook sees it exactly once, at the real entrypoint.
    /// (Checking twice would break one-shot grants such as MultiSigUpgradeGuard's.)
    function _runInner(address[] storage subs, address account, address target, uint256 value, bytes memory data)
        internal
    {
        if (target == account && data.length >= 4) {
            bytes4 s = bytes4(data);
            if (s == INSTALL_MODULE || s == UNINSTALL_MODULE) return;
        }
        _runAll(subs, account, target, value, data);
    }

    function _runAll(address[] storage subs, address account, address target, uint256 value, bytes memory data)
        internal
    {
        uint256 n = subs.length;
        for (uint256 i; i < n; i++) {
            ISubHook(subs[i]).preCheck(account, target, value, data);
        }
    }

    /// @dev ERC-7579 single execution: target(20) || value(32) || calldata
    function _decodeSingle(bytes memory ec) internal pure returns (address target, uint256 value, bytes memory data) {
        uint256 w;
        uint256 v;
        assembly {
            w := mload(add(ec, 32))
            v := mload(add(ec, 52))
        }
        target = address(uint160(w >> 96));
        value = v;
        uint256 len = ec.length - 52;
        data = new bytes(len);
        for (uint256 i; i < len; i++) {
            data[i] = ec[52 + i];
        }
    }
}
