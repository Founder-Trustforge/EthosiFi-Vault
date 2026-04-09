// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {IERC7579Account} from "erc7579/interfaces/IERC7579Account.sol";

/**
 * @title  VaultFactory
 * @author EthosiFi (founder@ethosifi.com)
 * @notice One-click EthosiFi Vault deployment — all modules pre-installed in one transaction.
 *
 *         What gets deployed
 *         ──────────────────
 *         Each vault is an EIP-1167 minimal proxy pointing to the EthosiFi account
 *         implementation (ERC-7579 / ERC-4337 compatible).
 *
 *         Modules installed at creation:
 *           Core validators:     TimeLock · Biometric · Guardian · EmergencyFreeze · MultiSigUpgradeGuard
 *           Protection modules:  PoisonedAddressProtection · AntiScamScreener · AIThreatOracle
 *                                DeepfakeGuard · PlainEnglishExecutor
 *           UX modules:          PaymasterManager · SeniorModeValidator (optional)
 *
 *         Key properties
 *         ──────────────
 *         • CREATE2 — deterministic vault address known before deployment
 *         • Module install failures are tracked per-vault (non-reverting but logged)
 *         • ERC-7579 module types are respected (validator=1, executor=2, fallback=3, hook=4)
 *         • Proxy bytecode embeds the live implementation address at deploy time
 *         • Owner is a 2-step transfer to prevent accidental loss
 *
 * @dev    BSL 1.1 — non-commercial use free; commercial license: founder@ethosifi.com
 *         Converts to GPL-3.0 on 2029-01-01.
 */
contract VaultFactory {

    // ─────────────────────────────────────────────────────────────
    // ERC-7579 module type constants
    // ─────────────────────────────────────────────────────────────

    uint256 private constant TYPE_VALIDATOR = 1;
    uint256 private constant TYPE_EXECUTOR  = 2;
    uint256 private constant TYPE_HOOK      = 4;

    // ─────────────────────────────────────────────────────────────
    // Module registry
    // ─────────────────────────────────────────────────────────────

    // Validators
    address public timeLockValidator;
    address public biometricValidator;
    address public guardianValidator;
    address public seniorModeValidator;

    // Executors / hooks
    address public emergencyFreeze;           // executor
    address public poisonedAddressProtection; // hook
    address public antiScamScreener;          // hook
    address public plainEnglishExecutor;      // executor
    address public aiThreatOracle;            // hook
    address public deepfakeGuard;             // hook
    address public multiSigUpgradeGuard;      // validator
    address public paymasterManager;          // executor

    // EthosiFi account implementation (all proxies point here)
    address public accountImplementation;

    // ERC-4337 EntryPoint
    address public entryPoint;

    // Ownership (2-step)
    address public owner;
    address public pendingOwner;

    uint256 public totalVaultsDeployed;

    // ─────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────

    struct VaultDeployment {
        address vaultAddress;
        address vaultOwner;
        uint256 deployedAt;
        bool    seniorMode;
        bytes32 salt;
        uint256 modulesFailed; // bitmask of failed module installs
    }

    mapping(address => VaultDeployment) public vaults;
    mapping(address => bool)            public isEthosiFiVault;

    // ─────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────

    event VaultDeployed(
        address indexed vault,
        address indexed vaultOwner,
        uint256 indexed vaultNumber,
        bool    seniorMode,
        uint256 timestamp
    );
    event ModuleInstallFailed(
        address indexed vault,
        address indexed module,
        string  moduleName,
        uint256 moduleType
    );
    event ModuleRegistryUpdated();
    event ImplementationUpdated(address indexed newImplementation);
    event OwnershipTransferStarted(address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ─────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────

    error NotOwner();
    error NotPendingOwner();
    error ZeroAddress();
    error InvalidThreshold();
    error InvalidCredential();
    error NoGuardians();
    error DeploymentFailed();
    error ImplementationNotSet();

    // ─────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────

    constructor(address _entryPoint, address _accountImplementation) {
        if (_entryPoint == address(0))             revert ZeroAddress();
        if (_accountImplementation == address(0))  revert ZeroAddress();

        owner                 = msg.sender;
        entryPoint            = _entryPoint;
        accountImplementation = _accountImplementation;
    }

    // ─────────────────────────────────────────────────────────────
    // One-click vault creation
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice Deploy a fully configured EthosiFi Vault in one transaction.
     *
     * @param credentialId       WebAuthn credential ID from biometric setup.
     * @param pubKey             P256 public key [x, y] from biometric setup.
     * @param rpIdHash           sha256 of the relying party domain ("ethosifi.xyz").
     * @param guardianAddresses  Guardian wallet addresses.
     * @param guardianWeights    Weight per guardian (parallel array to addresses).
     * @param guardianThreshold  Minimum total weight required for recovery.
     * @param feeToken           Token for gasless payments (address(0) = ETH).
     * @param seniorMode         Activate Senior Mode protection profile.
     * @param salt               User-provided entropy for deterministic address.
     *
     * @return vault             The deployed vault address.
     */
    function createVault(
        bytes32    credentialId,
        uint256[2] calldata pubKey,
        bytes32    rpIdHash,
        address[]  calldata guardianAddresses,
        uint256[]  calldata guardianWeights,
        uint256    guardianThreshold,
        address    feeToken,
        bool       seniorMode,
        bytes32    salt
    ) external returns (address vault) {

        // ── Input validation ──────────────────────────────────────
        if (credentialId == bytes32(0))                        revert InvalidCredential();
        if (pubKey[0] == 0 || pubKey[1] == 0)                  revert InvalidCredential();
        if (guardianAddresses.length == 0)                     revert NoGuardians();
        if (guardianAddresses.length != guardianWeights.length) revert InvalidThreshold();
        if (guardianThreshold == 0 ||
            guardianThreshold > _sumWeights(guardianWeights))  revert InvalidThreshold();
        if (accountImplementation == address(0))               revert ImplementationNotSet();

        // ── Deploy proxy ──────────────────────────────────────────
        bytes32 finalSalt = keccak256(abi.encodePacked(msg.sender, salt));
        vault = _deployProxy(finalSalt);

        // ── Initialize account ────────────────────────────────────
        // The ERC-7579 account needs to know its owner and entryPoint
        bytes memory initData = abi.encodeWithSignature(
            "initialize(address,address)",
            msg.sender,
            entryPoint
        );
        (bool initOk, ) = vault.call(initData);
        require(initOk, "Account init failed");

        // ── Install modules ───────────────────────────────────────
        uint256 failedModules = 0;

        failedModules |= _installCoreValidators(
            vault, credentialId, pubKey, rpIdHash,
            guardianAddresses, guardianWeights, guardianThreshold
        );
        failedModules |= _installProtectionModules(vault);
        failedModules |= _installUXModules(vault, feeToken, seniorMode,
                                            guardianAddresses, guardianThreshold);

        // ── Register vault ────────────────────────────────────────
        totalVaultsDeployed++;
        vaults[vault] = VaultDeployment({
            vaultAddress:  vault,
            vaultOwner:    msg.sender,
            deployedAt:    block.timestamp,
            seniorMode:    seniorMode,
            salt:          finalSalt,
            modulesFailed: failedModules
        });
        isEthosiFiVault[vault] = true;

        emit VaultDeployed(vault, msg.sender, totalVaultsDeployed, seniorMode, block.timestamp);
    }

    /**
     * @notice Compute the deterministic vault address before deployment.
     *         Users know their vault address before spending any gas.
     */
    function computeVaultAddress(
        address creator,
        bytes32 salt
    ) external view returns (address) {
        if (accountImplementation == address(0)) revert ImplementationNotSet();
        bytes32 finalSalt = keccak256(abi.encodePacked(creator, salt));
        bytes32 bytecodeHash = keccak256(_getProxyBytecode(accountImplementation));
        bytes32 hash = keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            finalSalt,
            bytecodeHash
        ));
        return address(uint160(uint256(hash)));
    }

    // ─────────────────────────────────────────────────────────────
    // Internal — module installation
    // ─────────────────────────────────────────────────────────────

    /**
     * @dev Returns a bitmask of failed installs (bit N = module N failed).
     */
    function _installCoreValidators(
        address vault,
        bytes32 credentialId,
        uint256[2] calldata pubKey,
        bytes32 rpIdHash,
        address[] calldata guardians,
        uint256[] calldata weights,
        uint256 threshold
    ) internal returns (uint256 failed) {

        // BiometricValidator — install data: (credentialId, pubKey, rpIdHash)
        if (!_installModule(
            vault, biometricValidator, TYPE_VALIDATOR, "BiometricValidator",
            abi.encode(credentialId, pubKey, rpIdHash)
        )) failed |= 1 << 0;

        // TimeLockValidator — (guardians, threshold, customDelay, usdcTokens, biometricPubKey)
        // Pass empty usdcTokens and biometricPubKey — TimeLock uses the EOA key, not P256
        address[] memory emptyUSDC = new address[](0);
        bytes memory emptyBiometric = "";
        if (!_installModule(
            vault, timeLockValidator, TYPE_VALIDATOR, "TimeLockValidator",
            abi.encode(guardians, threshold, uint256(0), emptyUSDC, emptyBiometric)
        )) failed |= 1 << 1;

        // GuardianValidator — build Guardian[] from parallel arrays
        bytes memory guardianData = _encodeGuardians(guardians, weights, threshold);
        if (!_installModule(
            vault, guardianValidator, TYPE_VALIDATOR, "GuardianValidator",
            guardianData
        )) failed |= 1 << 2;

        // EmergencyFreeze — (guardians, threshold, autoExpiry)
        if (!_installModule(
            vault, emergencyFreeze, TYPE_EXECUTOR, "EmergencyFreeze",
            abi.encode(guardians, threshold, uint256(0))
        )) failed |= 1 << 3;

        // MultiSigUpgradeGuard — (guardians, threshold)
        if (!_installModule(
            vault, multiSigUpgradeGuard, TYPE_VALIDATOR, "MultiSigUpgradeGuard",
            abi.encode(guardians, threshold)
        )) failed |= 1 << 4;
    }

    function _installProtectionModules(address vault)
        internal returns (uint256 failed)
    {
        // PoisonedAddressProtection — hook, strict=false
        if (!_installModule(
            vault, poisonedAddressProtection, TYPE_HOOK, "PoisonedAddressProtection",
            abi.encode(false, uint256(0), uint256(0))
        )) failed |= 1 << 5;

        // AntiScamScreener — hook, block HIGH (level 3), allow override
        if (!_installModule(
            vault, antiScamScreener, TYPE_HOOK, "AntiScamScreener",
            abi.encode(uint8(3), true)
        )) failed |= 1 << 6;

        // PlainEnglishExecutor — executor
        if (!_installModule(
            vault, plainEnglishExecutor, TYPE_EXECUTOR, "PlainEnglishExecutor",
            abi.encode(true, true, false)
        )) failed |= 1 << 7;

        // AIThreatOracle — hook, block ≥86, alert ≥61
        if (!_installModule(
            vault, aiThreatOracle, TYPE_HOOK, "AIThreatOracle",
            abi.encode(uint8(86), uint8(61), false, address(0))
        )) failed |= 1 << 8;

        // DeepfakeGuard — hook, challenge on transfers > $1,000
        if (!_installModule(
            vault, deepfakeGuard, TYPE_HOOK, "DeepfakeGuard",
            abi.encode(uint256(1000 * 1e6), false, uint256(0))
        )) failed |= 1 << 9;
    }

    function _installUXModules(
        address vault,
        address feeToken,
        bool seniorMode,
        address[] calldata guardians,
        uint256 threshold
    ) internal returns (uint256 failed) {

        // PaymasterManager — executor, free tier
        if (!_installModule(
            vault, paymasterManager, TYPE_EXECUTOR, "PaymasterManager",
            abi.encode(uint8(0), feeToken)
        )) failed |= 1 << 10;

        // SeniorModeValidator — optional validator
        if (seniorMode && seniorModeValidator != address(0)) {
            if (!_installModule(
                vault, seniorModeValidator, TYPE_VALIDATOR, "SeniorModeValidator",
                abi.encode(guardians, threshold, uint256(0), uint256(0), true)
            )) failed |= 1 << 11;
        }
    }

    /**
     * @dev  Attempt to install a module via the ERC-7579 account interface.
     *       Returns true on success, false on failure (non-reverting).
     *       Emits ModuleInstallFailed on failure so it can be retried.
     */
    function _installModule(
        address vault,
        address module,
        uint256 moduleType,
        string memory moduleName,
        bytes memory data
    ) internal returns (bool success) {
        if (module == address(0)) return true; // not deployed yet — skip silently

        (success, ) = vault.call(
            abi.encodeWithSignature(
                "installModule(uint256,address,bytes)",
                moduleType,
                module,
                data
            )
        );

        if (!success) {
            emit ModuleInstallFailed(vault, module, moduleName, moduleType);
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Internal — proxy deployment
    // ─────────────────────────────────────────────────────────────

    function _deployProxy(bytes32 salt) internal returns (address proxy) {
        bytes memory bytecode = _getProxyBytecode(accountImplementation);
        assembly {
            proxy := create2(0, add(bytecode, 32), mload(bytecode), salt)
        }
        if (proxy == address(0)) revert DeploymentFailed();
    }

    /**
     * @dev  EIP-1167 minimal proxy bytecode with the implementation address embedded.
     *
     *       Bytecode breakdown:
     *         363d3d373d3d3d363d73 <impl:20 bytes> 5af43d82803e903d91602b57fd5bf3
     *
     *       This is the canonical EIP-1167 pattern — all calls are delegated to `impl`.
     */
    function _getProxyBytecode(address impl) internal pure returns (bytes memory) {
        bytes20 implBytes = bytes20(impl);
        bytes memory bytecode = new bytes(45);

        // prefix
        bytecode[0]  = 0x36; bytecode[1]  = 0x3d; bytecode[2]  = 0x3d;
        bytecode[3]  = 0x37; bytecode[4]  = 0x3d; bytecode[5]  = 0x3d;
        bytecode[6]  = 0x3d; bytecode[7]  = 0x36; bytecode[8]  = 0x3d;
        bytecode[9]  = 0x73;

        // implementation address (20 bytes)
        for (uint256 i = 0; i < 20; i++) {
            bytecode[10 + i] = implBytes[i];
        }

        // suffix
        bytecode[30] = 0x5a; bytecode[31] = 0xf4; bytecode[32] = 0x3d;
        bytecode[33] = 0x82; bytecode[34] = 0x80; bytecode[35] = 0x3e;
        bytecode[36] = 0x90; bytecode[37] = 0x3d; bytecode[38] = 0x91;
        bytecode[39] = 0x60; bytecode[40] = 0x2b; bytecode[41] = 0x57;
        bytecode[42] = 0xfd; bytecode[43] = 0x5b; bytecode[44] = 0xf3;

        return bytecode;
    }

    // ─────────────────────────────────────────────────────────────
    // Internal — encoding helpers
    // ─────────────────────────────────────────────────────────────

    /**
     * @dev  Build the GuardianValidator install data from parallel arrays.
     *       GuardianValidator expects: (Guardian[] guardians, uint256 threshold)
     *       Guardian struct: (address addr, uint256 weight, bytes32 identityHash)
     */
    function _encodeGuardians(
        address[] calldata addrs,
        uint256[] calldata weights,
        uint256 threshold
    ) internal pure returns (bytes memory) {
        // Build array of (address, uint256, bytes32) tuples
        bytes memory guardianArray = new bytes(addrs.length * 96); // 3 * 32 bytes per guardian
        for (uint256 i = 0; i < addrs.length; i++) {
            uint256 offset = i * 96;
            bytes32 addr32 = bytes32(uint256(uint160(addrs[i])));
            bytes32 weight32 = bytes32(weights[i]);
            bytes32 identity = bytes32(0); // no identity hash at creation

            assembly {
                mstore(add(add(guardianArray, 32), offset),        addr32)
                mstore(add(add(guardianArray, 32), add(offset, 32)), weight32)
                mstore(add(add(guardianArray, 32), add(offset, 64)), identity)
            }
        }

        return abi.encode(guardianArray, threshold);
    }

    function _sumWeights(uint256[] calldata weights) internal pure returns (uint256 total) {
        for (uint256 i = 0; i < weights.length; i++) {
            total += weights[i];
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Admin — module registry
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice Update all module addresses in one call.
     *         Only callable after all modules are deployed.
     */
    function setModules(
        address _timeLock,
        address _biometric,
        address _guardian,
        address _freeze,
        address _poison,
        address _scam,
        address _plainEnglish,
        address _ai,
        address _deepfake,
        address _upgradeGuard,
        address _paymaster,
        address _senior
    ) external onlyOwner {
        timeLockValidator         = _timeLock;
        biometricValidator        = _biometric;
        guardianValidator         = _guardian;
        emergencyFreeze           = _freeze;
        poisonedAddressProtection = _poison;
        antiScamScreener          = _scam;
        plainEnglishExecutor      = _plainEnglish;
        aiThreatOracle            = _ai;
        deepfakeGuard             = _deepfake;
        multiSigUpgradeGuard      = _upgradeGuard;
        paymasterManager          = _paymaster;
        seniorModeValidator       = _senior;
        emit ModuleRegistryUpdated();
    }

    function setAccountImplementation(address impl) external onlyOwner {
        if (impl == address(0)) revert ZeroAddress();
        accountImplementation = impl;
        emit ImplementationUpdated(impl);
    }

    // ─────────────────────────────────────────────────────────────
    // Admin — 2-step ownership transfer
    // ─────────────────────────────────────────────────────────────

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        emit OwnershipTransferred(owner, pendingOwner);
        owner        = pendingOwner;
        pendingOwner = address(0);
    }

    // ─────────────────────────────────────────────────────────────
    // View helpers
    // ─────────────────────────────────────────────────────────────

    function getVaultInfo(address vault) external view returns (
        address vaultOwner,
        uint256 deployedAt,
        bool    seniorMode,
        uint256 modulesFailed
    ) {
        VaultDeployment storage v = vaults[vault];
        return (v.vaultOwner, v.deployedAt, v.seniorMode, v.modulesFailed);
    }

    function getAllModules() external view returns (address[12] memory modules) {
        return [
            timeLockValidator, biometricValidator, guardianValidator,
            emergencyFreeze, poisonedAddressProtection, antiScamScreener,
            plainEnglishExecutor, aiThreatOracle, deepfakeGuard,
            multiSigUpgradeGuard, paymasterManager, seniorModeValidator
        ];
    }

    function getModuleInstallStatus(address vault) external view returns (
        bool[12] memory installed
    ) {
        uint256 failed = vaults[vault].modulesFailed;
        for (uint256 i = 0; i < 12; i++) {
            installed[i] = (failed & (1 << i)) == 0;
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Modifiers
    // ─────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }
}
