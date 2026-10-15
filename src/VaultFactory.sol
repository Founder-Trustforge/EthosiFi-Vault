// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {MSAProxy} from "erc7579/utils/MSAProxy.sol";
import {IMSA} from "erc7579/interfaces/IMSA.sol";
import {BootstrapConfig} from "erc7579/utils/Bootstrap.sol";
import {EthosiBootstrap} from "./EthosiBootstrap.sol";
import {TimeLockValidator} from "./TimeLockValidator.sol";
import {GuardianValidator} from "./GuardianValidator.sol";

interface IEntryPointDeposit {
    function depositTo(address account) external payable;
}

/**
 * @title VaultFactory
 * @notice Deploys EthosiFi Vaults: ERC-4337 / ERC-7579 modular smart accounts (rhinestone `MSAAdvanced`
 * behind an `MSAProxy`) with the full protection stack wired up atomically in the proxy constructor,
 * so a vault can never exist half-configured (no front-running window between deploy and setup).
 *
 *   Authorities
 *     - passkey / fingerprint (BiometricValidator)  full authority
 *     - spending key (TimeLockValidator)             small, rate-limited transfers only
 *     - guardians (GuardianValidator)                time-delayed passkey recovery only
 *   Policy (all behind EthosiHookRouter, the account's single hook)
 *     - TimeLockValidator velocity budget (always), plus the allow-listed policy hooks you choose
 *
 * The factory has NO owner and NO admin functions: every address it uses is immutable.
 * The account address is a pure function of (salt, config) and can be computed off-chain.
 */
contract VaultFactory {
    address public immutable entryPoint;
    address public immutable accountImplementation;
    address public immutable bootstrap;
    address public immutable router;
    address public immutable biometricValidator;
    address public immutable timeLockValidator;
    address public immutable guardianValidator;

    /// @dev policy sub-hooks users may choose (fixed at construction)
    mapping(address => bool) public isAllowedSubHook;

    struct SubHookInit {
        address module;
        bytes data; // abi-encoded onInstall data for that module
    }

    struct VaultConfig {
        // fingerprint (passkey)
        bytes32 credentialId;
        uint256[2] passkeyPubKey;
        bytes32 rpIdHash; // sha256("ethosifi.com")
        // spending key + delayed-tx settings (TimeLockValidator)
        address spendingSigner;
        address[] cancelGuardians;
        uint256 delay; // 0 => 48h
        TimeLockValidator.InitPolicy[] policies;
        // social recovery (GuardianValidator)
        GuardianValidator.Guardian[] recoveryGuardians;
        uint256 recoveryThreshold;
        // optional policy hooks, each must be in the factory allow-list
        SubHookInit[] subHooks;
    }

    event VaultCreated(address indexed account, bytes32 indexed salt, bytes32 indexed credentialId);

    error ZeroAddress();
    error SubHookNotAllowed(address module);
    error DuplicateSubHook(address module);
    error EmptyRecoveryConfig();

    constructor(
        address entryPoint_,
        address accountImplementation_,
        address bootstrap_,
        address router_,
        address biometricValidator_,
        address timeLockValidator_,
        address guardianValidator_,
        address[] memory allowedSubHooks
    ) {
        if (
            entryPoint_ == address(0) || accountImplementation_ == address(0) || bootstrap_ == address(0)
                || router_ == address(0) || biometricValidator_ == address(0) || timeLockValidator_ == address(0)
                || guardianValidator_ == address(0)
        ) revert ZeroAddress();
        entryPoint = entryPoint_;
        accountImplementation = accountImplementation_;
        bootstrap = bootstrap_;
        router = router_;
        biometricValidator = biometricValidator_;
        timeLockValidator = timeLockValidator_;
        guardianValidator = guardianValidator_;
        for (uint256 i; i < allowedSubHooks.length; i++) {
            if (allowedSubHooks[i] == address(0)) revert ZeroAddress();
            isAllowedSubHook[allowedSubHooks[i]] = true;
        }
    }

    /// @notice Deploy (or return the already-deployed) vault for `cfg`. Permissionless: the address
    /// depends on every field of `cfg`, so nobody can deploy a different vault at your address.
    /// `msg.value` is deposited into the vault's EntryPoint deposit (its GAS TANK): the spending key
    /// can only ever spend gas from that tank, never from the vault's balance.
    function createVault(bytes32 salt, VaultConfig calldata cfg) external payable returns (address account) {
        bytes memory initData = _initData(cfg);
        account = _predict(salt, initData);
        if (account.code.length == 0) {
            address deployed = address(
                new MSAProxy{salt: salt}(accountImplementation, abi.encodeCall(IMSA.initializeAccount, initData))
            );
            assert(deployed == account);
            emit VaultCreated(account, salt, cfg.credentialId);
        }
        if (msg.value != 0) IEntryPointDeposit(entryPoint).depositTo{value: msg.value}(account);
    }

    /// @notice Counterfactual address of the vault for (`salt`, `cfg`).
    function getAddress(bytes32 salt, VaultConfig calldata cfg) external view returns (address) {
        return _predict(salt, _initData(cfg));
    }

    // ─── internals ────────────────────────────────────────────────────────────

    function _predict(bytes32 salt, bytes memory initData) internal view returns (address) {
        bytes32 h = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(
                    abi.encodePacked(
                        type(MSAProxy).creationCode,
                        abi.encode(accountImplementation, abi.encodeCall(IMSA.initializeAccount, initData))
                    )
                )
            )
        );
        return address(uint160(uint256(h)));
    }

    /// @dev abi.encode(bootstrap, bootstrapCall) as expected by MSAAdvanced.initializeAccount
    function _initData(VaultConfig calldata cfg) internal view returns (bytes memory) {
        if (cfg.recoveryGuardians.length == 0) revert EmptyRecoveryConfig();

        BootstrapConfig[] memory validators = new BootstrapConfig[](2);
        validators[0] =
            BootstrapConfig(biometricValidator, abi.encode(cfg.credentialId, cfg.passkeyPubKey, cfg.rpIdHash));
        bytes memory tlData = abi.encode(cfg.spendingSigner, cfg.cancelGuardians, cfg.delay, cfg.policies);
        validators[1] = BootstrapConfig(timeLockValidator, tlData);

        BootstrapConfig[] memory executors = new BootstrapConfig[](2);
        executors[0] = BootstrapConfig(timeLockValidator, tlData); // idempotent second install
        executors[1] = BootstrapConfig(guardianValidator, abi.encode(cfg.recoveryGuardians, cfg.recoveryThreshold));

        // sub-hooks: TimeLock budget first (always), then the user's allow-listed policy hooks
        uint256 n = cfg.subHooks.length;
        BootstrapConfig[] memory subs = new BootstrapConfig[](n + 1);
        subs[0] = BootstrapConfig(timeLockValidator, ""); // already initialised as a validator
        for (uint256 i; i < n; i++) {
            address m = cfg.subHooks[i].module;
            if (!isAllowedSubHook[m]) revert SubHookNotAllowed(m);
            for (uint256 j; j < i; j++) {
                if (cfg.subHooks[j].module == m) revert DuplicateSubHook(m);
            }
            subs[i + 1] = BootstrapConfig(m, cfg.subHooks[i].data);
        }

        return abi.encode(bootstrap, abi.encodeCall(EthosiBootstrap.initVault, (validators, executors, subs, router)));
    }
}
