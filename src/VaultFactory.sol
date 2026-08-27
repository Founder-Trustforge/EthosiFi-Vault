// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {IERC7579Account} from "erc7579/interfaces/IERC7579Account.sol";
import {ReentrancyGuard} from "solady/utils/ReentrancyGuard.sol";

/**
 * @title  VaultFactory
 * @author EthosiFi (founder@ethosifi.com)
 * @notice One-click EthosiFi Vault deployment — all modules pre-installed.
 *
 * @dev    SECURITY FIXES (2026-08 audit):
 *         [CRIT-1] _getProxyBytecode() built the 45-byte EIP-1167 runtime body
 *                  and passed it directly to CREATE2 as init code. CREATE2 executed
 *                  it as a constructor, which delegatecalled the implementation with
 *                  empty calldata, returned zero bytes, and deployed a codeless address.
 *                  All ETH sent to such a vault is permanently unrecoverable.
 *                  Fixed: prepend the 10-byte deployer stub (3d602d80600a3d3981f3).
 *         [CRIT-2] No post-deploy extcodesize check. Fixed: revert if deployed
 *                  address has zero code.
 *         [HIGH-1] createVault() had no reentrancy guard. Fixed: ReentrancyGuard.
 *         [MED-1]  transferOwnership() was one-step. Fixed: two-step with pendingOwner.
 */
contract VaultFactory is ReentrancyGuard {

    uint256 private constant TYPE_VALIDATOR = 1;
    uint256 private constant TYPE_EXECUTOR  = 2;
    uint256 private constant TYPE_HOOK      = 4;

    // ─── Module registry ──────────────────────────────────────────────────────

    address public timeLockValidator;
    address public biometricValidator;
    address public guardianValidator;
    address public seniorModeValidator;
    address public emergencyFreeze;
    address public poisonedAddressProtection;
    address public antiScamScreener;
    address public plainEnglishExecutor;
    address public aiThreatOracle;
    address public deepfakeGuard;
    address public multiSigUpgradeGuard;
    address public paymasterManager;
    address public accountImplementation;
    address public entryPoint;

    // ─── Ownership ────────────────────────────────────────────────────────────

    address public owner;
    address public pendingOwner;

    uint256 public totalVaultsDeployed;

    struct VaultDeployment {
        address vaultAddress;
        address vaultOwner;
        uint256 deployedAt;
        bool    seniorMode;
        bytes32 salt;
        uint256 modulesFailed;
    }

    mapping(address => VaultDeployment) public vaults;
    mapping(address => bool)            public isEthosiFiVault;

    // ─── Events ───────────────────────────────────────────────────────────────

    event VaultDeployed(address indexed vault, address indexed vaultOwner, uint256 indexed vaultNumber, bool seniorMode, uint256 timestamp);
    event ModuleInstallFailed(address indexed vault, address indexed module, string moduleName, uint256 moduleType);
    event ModuleRegistryUpdated();
    event ImplementationUpdated(address indexed newImplementation);
    event OwnershipTransferStarted(address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ─── Errors ───────────────────────────────────────────────────────────────

    error NotOwner();
    error NotPendingOwner();
    error ZeroAddress();
    error InvalidThreshold();
    error InvalidCredential();
    error NoGuardians();
    error DeploymentFailed();
    error ImplementationNotSet();
    error CodelessVaultDetected();

    // ─── Constructor ──────────────────────────────────────────────────────────

    constructor(address _entryPoint, address _accountImplementation) {
        if (_entryPoint == address(0))            revert ZeroAddress();
        if (_accountImplementation == address(0)) revert ZeroAddress();
        owner                 = msg.sender;
        entryPoint            = _entryPoint;
        accountImplementation = _accountImplementation;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // ─── Vault creation ───────────────────────────────────────────────────────

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
    ) external nonReentrant returns (address vault) {

        if (credentialId == bytes32(0))                         revert InvalidCredential();
        if (pubKey[0] == 0 || pubKey[1] == 0)                   revert InvalidCredential();
        if (guardianAddresses.length == 0)                      revert NoGuardians();
        if (guardianAddresses.length != guardianWeights.length) revert InvalidThreshold();
        if (guardianThreshold == 0 ||
            guardianThreshold > _sumWeights(guardianWeights))   revert InvalidThreshold();
        if (accountImplementation == address(0))                revert ImplementationNotSet();

        bytes32 finalSalt = keccak256(abi.encodePacked(msg.sender, salt));
        vault = _deployProxy(finalSalt);

        bytes memory initData = abi.encodeWithSignature(
            "initialize(address,address)", msg.sender, entryPoint
        );
        (bool initOk,) = vault.call(initData);
        require(initOk, "Account init failed");

        uint256 failedModules = 0;
        failedModules |= _installCoreValidators(vault, credentialId, pubKey, rpIdHash, guardianAddresses, guardianWeights, guardianThreshold);
        failedModules |= _installProtectionModules(vault);
        failedModules |= _installUXModules(vault, feeToken, seniorMode, guardianAddresses, guardianThreshold);

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

    function computeVaultAddress(address creator, bytes32 salt) external view returns (address) {
        if (accountImplementation == address(0)) revert ImplementationNotSet();
        bytes32 finalSalt    = keccak256(abi.encodePacked(creator, salt));
        // [CRIT-1] Use creation bytecode hash (55 bytes) not runtime bytecode hash (45 bytes)
        bytes32 bytecodeHash = keccak256(_getProxyBytecode(accountImplementation));
        bytes32 hash = keccak256(abi.encodePacked(
            bytes1(0xff), address(this), finalSalt, bytecodeHash
        ));
        return address(uint160(uint256(hash)));
    }

    // ─── Module installation ──────────────────────────────────────────────────

    function _installCoreValidators(
        address vault,
        bytes32 credentialId,
        uint256[2] calldata pubKey,
        bytes32 rpIdHash,
        address[] calldata guardians,
        uint256[] calldata weights,
        uint256 threshold
    ) internal returns (uint256 failed) {
        if (!_installModule(vault, biometricValidator, TYPE_VALIDATOR, "BiometricValidator",
            abi.encode(credentialId, pubKey, rpIdHash))) failed |= 1 << 0;

        address[] memory emptyUSDC = new address[](0);
        if (!_installModule(vault, timeLockValidator, TYPE_VALIDATOR, "TimeLockValidator",
            abi.encode(guardians, threshold, uint256(0), emptyUSDC, ""))) failed |= 1 << 1;

        if (!_installModule(vault, guardianValidator, TYPE_VALIDATOR, "GuardianValidator",
            _encodeGuardians(guardians, weights, threshold))) failed |= 1 << 2;

        if (!_installModule(vault, emergencyFreeze, TYPE_EXECUTOR, "EmergencyFreeze",
            abi.encode(guardians, threshold, uint256(0)))) failed |= 1 << 3;

        if (!_installModule(vault, multiSigUpgradeGuard, TYPE_VALIDATOR, "MultiSigUpgradeGuard",
            abi.encode(guardians, threshold))) failed |= 1 << 4;
    }

    function _installProtectionModules(address vault) internal returns (uint256 failed) {
        if (!_installModule(vault, poisonedAddressProtection, TYPE_HOOK, "PoisonedAddressProtection",
            abi.encode(false, uint256(0), uint256(0)))) failed |= 1 << 5;

        if (!_installModule(vault, antiScamScreener, TYPE_HOOK, "AntiScamScreener",
            abi.encode(uint8(3), true))) failed |= 1 << 6;

        if (!_installModule(vault, plainEnglishExecutor, TYPE_EXECUTOR, "PlainEnglishExecutor",
            abi.encode(true, true, false))) failed |= 1 << 7;

        if (!_installModule(vault, aiThreatOracle, TYPE_HOOK, "AIThreatOracle",
            abi.encode(uint256(75), true, uint256(0)))) failed |= 1 << 8;

        if (!_installModule(vault, deepfakeGuard, TYPE_HOOK, "DeepfakeGuard",
            abi.encode(false, uint256(70), new address[](0), uint256(1), uint256(0)))) failed |= 1 << 9;
    }

    function _installUXModules(
        address vault,
        address feeToken,
        bool seniorMode,
        address[] calldata guardians,
        uint256 threshold
    ) internal returns (uint256 failed) {
        if (!_installModule(vault, paymasterManager, TYPE_EXECUTOR, "PaymasterManager",
            abi.encode(uint8(0), feeToken))) failed |= 1 << 10;

        if (seniorMode && seniorModeValidator != address(0)) {
            if (!_installModule(vault, seniorModeValidator, TYPE_VALIDATOR, "SeniorModeValidator",
                abi.encode(uint256(0), uint256(0), guardians, threshold, true))) failed |= 1 << 11;
        }
    }

    function _installModule(
        address vault,
        address module,
        uint256 moduleType,
        string memory moduleName,
        bytes memory data
    ) internal returns (bool success) {
        if (module == address(0)) return true;
        (success,) = vault.call(abi.encodeWithSignature(
            "installModule(uint256,address,bytes)", moduleType, module, data
        ));
        if (!success) emit ModuleInstallFailed(vault, module, moduleName, moduleType);
    }

    // ─── Proxy deployment ─────────────────────────────────────────────────────

    function _deployProxy(bytes32 salt) internal returns (address proxy) {
        bytes memory bytecode = _getProxyBytecode(accountImplementation);
        assembly {
            proxy := create2(0, add(bytecode, 32), mload(bytecode), salt)
        }
        if (proxy == address(0)) revert DeploymentFailed();

        // [CRIT-2] Post-deploy safety: a correctly deployed EIP-1167 proxy must have code.
        uint256 codeSize;
        assembly { codeSize := extcodesize(proxy) }
        if (codeSize == 0) revert CodelessVaultDetected();
    }

    /**
     * @dev EIP-1167 CREATION code = 10-byte deployer stub + 45-byte runtime = 55 bytes.
     *
     *      [CRIT-1] Previously this function returned only the 45-byte runtime body.
     *      When passed to CREATE2 as init code, the EVM executed the runtime body as a
     *      constructor: it delegatecalled the implementation with empty calldata, got back
     *      zero bytes, and deployed a codeless address. CREATE2 reported success, events
     *      were emitted, but every vault was permanently codeless. Any ETH sent to it
     *      was unrecoverable.
     *
     *      Fix: prepend the 10-byte deployer stub that copies the 45-byte runtime body
     *      into memory and returns it as the deployed code.
     *
     *      Stub bytes: 3d 60 2d 80 60 0a 3d 39 81 f3
     *        3d  RETURNDATASIZE  (0)
     *        60 2d PUSH1 45      (length of runtime body)
     *        80  DUP1
     *        60 0a PUSH1 10      (offset of runtime body in this init code)
     *        3d  RETURNDATASIZE  (0 — destination in memory)
     *        39  CODECOPY        (copy 45 bytes from offset 10 into mem[0..44])
     *        81  DUP2
     *        f3  RETURN          (return mem[0..44] as deployed code)
     */
    function _getProxyBytecode(address impl) internal pure returns (bytes memory) {
        bytes20 implBytes = bytes20(impl);
        bytes memory bytecode = new bytes(55); // 10-byte stub + 45-byte runtime

        // ── 10-byte deployer stub ─────────────────────────────────────────────
        bytecode[0] = 0x3d; bytecode[1] = 0x60; bytecode[2] = 0x2d;
        bytecode[3] = 0x80; bytecode[4] = 0x60; bytecode[5] = 0x0a;
        bytecode[6] = 0x3d; bytecode[7] = 0x39; bytecode[8] = 0x81;
        bytecode[9] = 0xf3;

        // ── 45-byte EIP-1167 runtime body ────────────────────────────────────
        // prefix: calldatacopy boilerplate
        bytecode[10] = 0x36; bytecode[11] = 0x3d; bytecode[12] = 0x3d;
        bytecode[13] = 0x37; bytecode[14] = 0x3d; bytecode[15] = 0x3d;
        bytecode[16] = 0x3d; bytecode[17] = 0x36; bytecode[18] = 0x3d;
        bytecode[19] = 0x73;

        // implementation address (20 bytes at positions 20-39)
        for (uint256 i = 0; i < 20; i++) {
            bytecode[20 + i] = implBytes[i];
        }

        // suffix: delegatecall + return/revert
        bytecode[40] = 0x5a; bytecode[41] = 0xf4; bytecode[42] = 0x3d;
        bytecode[43] = 0x82; bytecode[44] = 0x80; bytecode[45] = 0x3e;
        bytecode[46] = 0x90; bytecode[47] = 0x3d; bytecode[48] = 0x91;
        bytecode[49] = 0x60; bytecode[50] = 0x2b; bytecode[51] = 0x57;
        bytecode[52] = 0xfd; bytecode[53] = 0x5b; bytecode[54] = 0xf3;

        return bytecode;
    }

    // ─── Encoding helpers ─────────────────────────────────────────────────────

    function _encodeGuardians(
        address[] calldata addrs,
        uint256[] calldata weights,
        uint256 threshold
    ) internal pure returns (bytes memory) {
        bytes memory arr = new bytes(addrs.length * 96);
        for (uint256 i = 0; i < addrs.length; i++) {
            uint256 offset = i * 96;
            bytes32 addr32   = bytes32(uint256(uint160(addrs[i])));
            bytes32 weight32 = bytes32(weights[i]);
            bytes32 identity = bytes32(0);
            assembly {
                mstore(add(add(arr, 32), offset),            addr32)
                mstore(add(add(arr, 32), add(offset, 32)),   weight32)
                mstore(add(add(arr, 32), add(offset, 64)),   identity)
            }
        }
        return abi.encode(arr, threshold);
    }

    function _sumWeights(uint256[] calldata weights) internal pure returns (uint256 total) {
        for (uint256 i = 0; i < weights.length; i++) total += weights[i];
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    function setModules(
        address _timeLock, address _biometric, address _guardian,
        address _freeze,   address _poison,    address _scam,
        address _plainEnglish, address _ai,    address _deepfake,
        address _upgradeGuard, address _paymaster, address _senior
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

    // ─── View ─────────────────────────────────────────────────────────────────

    function getVaultInfo(address vault) external view returns (
        address vaultOwner, uint256 deployedAt, bool seniorMode, uint256 modulesFailed
    ) {
        VaultDeployment storage v = vaults[vault];
        return (v.vaultOwner, v.deployedAt, v.seniorMode, v.modulesFailed);
    }

    function getAllModules() external view returns (address[12] memory modules) {
        return [timeLockValidator, biometricValidator, guardianValidator,
                emergencyFreeze, poisonedAddressProtection, antiScamScreener,
                plainEnglishExecutor, aiThreatOracle, deepfakeGuard,
                multiSigUpgradeGuard, paymasterManager, seniorModeValidator];
    }

    function getModuleInstallStatus(address vault) external view returns (bool[12] memory installed) {
        uint256 failed = vaults[vault].modulesFailed;
        for (uint256 i = 0; i < 12; i++) installed[i] = (failed & (1 << i)) == 0;
    }
}
