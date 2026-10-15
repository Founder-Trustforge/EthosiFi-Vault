// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {Bootstrap, BootstrapConfig} from "erc7579/utils/Bootstrap.sol";
import {IModule, IHook} from "erc7579/interfaces/IERC7579Module.sol";

/**
 * @title EthosiBootstrap
 * @notice Delegatecalled by the account during `initializeAccount` (see VaultFactory). Because it
 * runs in the account's context, every module's `onInstall` sees msg.sender == the new account.
 *
 *  1. validators (BiometricValidator, TimeLockValidator)
 *  2. executors  (TimeLockValidator, GuardianValidator)
 *  3. sub-hook `onInstall`s (per-account policy modules gated behind the router)
 *  4. the router, installed in the account's single hook slot with its sub-hook list
 */
contract EthosiBootstrap is Bootstrap {
    function initVault(
        BootstrapConfig[] calldata validators,
        BootstrapConfig[] calldata executors,
        BootstrapConfig[] calldata subHooks,
        address router
    ) external {
        for (uint256 i; i < validators.length; i++) {
            _installValidator(validators[i].module, validators[i].data);
        }
        for (uint256 i; i < executors.length; i++) {
            _installExecutor(executors[i].module, executors[i].data);
        }

        address[] memory subs = new address[](subHooks.length);
        for (uint256 i; i < subHooks.length; i++) {
            subs[i] = subHooks[i].module;
            // TimeLockValidator is both a module and a sub-hook; it is already initialised by
            // its validator install, and its onInstall is idempotent. Pure policy hooks init here.
            if (subHooks[i].data.length != 0) IModule(subHooks[i].module).onInstall(subHooks[i].data);
        }
        // same as HookManager._installHook, but with in-memory init data
        address current = _getHook();
        if (current != address(0)) revert HookAlreadyInstalled(current);
        _setHook(router);
        IHook(router).onInstall(abi.encode(subs));
    }
}
