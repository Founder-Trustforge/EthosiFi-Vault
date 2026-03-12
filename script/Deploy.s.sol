// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import "../src/TimeLockValidator.sol";
import "../src/BiometricValidator.sol";
import "../src/GuardianValidator.sol";
import "../src/EmergencyFreeze.sol";
import "../src/MultiSigUpgradeGuard.sol";
import "../src/PoisonedAddressProtection.sol";
import "../src/AntiScamScreener.sol";
import "../src/PlainEnglishExecutor.sol";
import "../src/AIThreatOracle.sol";
import "../src/DeepfakeGuard.sol";
import "../src/SeniorModeValidator.sol";
import "../src/PaymasterManager.sol";
import "../src/VaultFactory.sol";

/**
 * @title DeployScript
 * @notice EthosiFi Vault — Full deployment script for all 13 contracts.
 *
 * Usage:
 *   Sepolia:  forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC --broadcast --verify
 *   Mainnet:  forge script script/Deploy.s.sol --rpc-url $MAINNET_RPC --broadcast --verify
 *
 * Required env vars:
 *   PRIVATE_KEY       — Deployer private key
 *   SEPOLIA_RPC       — Sepolia RPC URL (Alchemy/Infura)
 *   MAINNET_RPC       — Mainnet RPC URL
 *   ETHERSCAN_API_KEY — For contract verification
 *   ENTRY_POINT       — ERC-4337 EntryPoint address
 *   USDC_ADDRESS      — USDC token address on target network
 */
contract DeployScript is Script {

    // ERC-4337 EntryPoint (canonical across all EVM chains)
    address constant ENTRY_POINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
    address constant ENTRY_POINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    struct Addresses {
        address timeLockValidator;
        address biometricValidator;
        address guardianValidator;
        address emergencyFreeze;
        address multiSigUpgradeGuard;
        address poisonedAddressProtection;
        address antiScamScreener;
        address plainEnglishExecutor;
        address aiThreatOracle;
        address deepfakeGuard;
        address seniorModeValidator;
        address paymasterManager;
        address vaultFactory;
    }

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address entryPoint = vm.envOr("ENTRY_POINT", ENTRY_POINT_V07);

        console.log("====================================================");
        console.log("  EthosiFi Vault - Full Deployment");
        console.log("====================================================");
        console.log("  Deployer:    ", deployer);
        console.log("  EntryPoint:  ", entryPoint);
        console.log("  Chain ID:    ", block.chainid);
        console.log("  Block:       ", block.number);
        console.log("====================================================");

        vm.startBroadcast(deployerPrivateKey);

        Addresses memory addrs;

        // ── Layer 1: Core Security ────────────────────────────
        console.log("\n[1/4] Deploying Core Security Contracts...");

        addrs.timeLockValidator = address(new TimeLockValidator());
        console.log("  TimeLockValidator:       ", addrs.timeLockValidator);

        addrs.biometricValidator = address(new BiometricValidator());
        console.log("  BiometricValidator:      ", addrs.biometricValidator);

        addrs.guardianValidator = address(new GuardianValidator());
        console.log("  GuardianValidator:       ", addrs.guardianValidator);

        addrs.emergencyFreeze = address(new EmergencyFreeze());
        console.log("  EmergencyFreeze:         ", addrs.emergencyFreeze);

        addrs.multiSigUpgradeGuard = address(new MultiSigUpgradeGuard());
        console.log("  MultiSigUpgradeGuard:    ", addrs.multiSigUpgradeGuard);

        // ── Layer 2: User Protection ──────────────────────────
        console.log("\n[2/4] Deploying User Protection Contracts...");

        addrs.poisonedAddressProtection = address(new PoisonedAddressProtection());
        console.log("  PoisonedAddressProtection:", addrs.poisonedAddressProtection);

        addrs.antiScamScreener = address(new AntiScamScreener());
        console.log("  AntiScamScreener:        ", addrs.antiScamScreener);

        addrs.plainEnglishExecutor = address(new PlainEnglishExecutor());
        console.log("  PlainEnglishExecutor:    ", addrs.plainEnglishExecutor);

        addrs.aiThreatOracle = address(new AIThreatOracle());
        console.log("  AIThreatOracle:          ", addrs.aiThreatOracle);

        addrs.deepfakeGuard = address(new DeepfakeGuard());
        console.log("  DeepfakeGuard:           ", addrs.deepfakeGuard);

        // ── Layer 3: UX & Accessibility ───────────────────────
        console.log("\n[3/4] Deploying UX & Accessibility Contracts...");

        addrs.seniorModeValidator = address(new SeniorModeValidator());
        console.log("  SeniorModeValidator:     ", addrs.seniorModeValidator);

        addrs.paymasterManager = address(new PaymasterManager());
        console.log("  PaymasterManager:        ", addrs.paymasterManager);

        // ── Layer 4: Infrastructure ───────────────────────────
        console.log("\n[4/4] Deploying Infrastructure...");

        VaultFactory factory = new VaultFactory(entryPoint);
        addrs.vaultFactory = address(factory);
        console.log("  VaultFactory:            ", addrs.vaultFactory);

        // Register all modules in VaultFactory
        factory.setModules(
            addrs.timeLockValidator,
            addrs.biometricValidator,
            addrs.guardianValidator,
            addrs.emergencyFreeze,
            addrs.poisonedAddressProtection,
            addrs.antiScamScreener,
            addrs.plainEnglishExecutor,
            addrs.aiThreatOracle,
            addrs.deepfakeGuard,
            addrs.multiSigUpgradeGuard,
            addrs.paymasterManager,
            addrs.seniorModeValidator
        );
        console.log("  VaultFactory modules registered.");

        vm.stopBroadcast();

        // ── Deployment Summary ────────────────────────────────
        console.log("\n====================================================");
        console.log("  DEPLOYMENT COMPLETE");
        console.log("====================================================");
        console.log("  Copy these addresses to your .env and frontend:");
        console.log("====================================================");
        console.log("  TIMELOCK_VALIDATOR=       ", addrs.timeLockValidator);
        console.log("  BIOMETRIC_VALIDATOR=      ", addrs.biometricValidator);
        console.log("  GUARDIAN_VALIDATOR=       ", addrs.guardianValidator);
        console.log("  EMERGENCY_FREEZE=         ", addrs.emergencyFreeze);
        console.log("  MULTISIG_UPGRADE_GUARD=   ", addrs.multiSigUpgradeGuard);
        console.log("  POISONED_ADDRESS=         ", addrs.poisonedAddressProtection);
        console.log("  ANTI_SCAM_SCREENER=       ", addrs.antiScamScreener);
        console.log("  PLAIN_ENGLISH_EXECUTOR=   ", addrs.plainEnglishExecutor);
        console.log("  AI_THREAT_ORACLE=         ", addrs.aiThreatOracle);
        console.log("  DEEPFAKE_GUARD=           ", addrs.deepfakeGuard);
        console.log("  SENIOR_MODE_VALIDATOR=    ", addrs.seniorModeValidator);
        console.log("  PAYMASTER_MANAGER=        ", addrs.paymasterManager);
        console.log("  VAULT_FACTORY=            ", addrs.vaultFactory);
        console.log("====================================================");
        console.log("  Next: Verify contracts on Etherscan");
        console.log("  forge verify-contract <address> <ContractName>");
        console.log("====================================================");
    }
}
