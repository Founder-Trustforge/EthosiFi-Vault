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

contract DeployScript is Script {

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
        console.log("  Deployer:   ", deployer);
        console.log("  EntryPoint: ", entryPoint);
        console.log("  Chain ID:   ", block.chainid);
        console.log("====================================================");

        vm.startBroadcast(deployerPrivateKey);

        Addresses memory addrs;

        console.log("\n[1/4] Core Security...");
        addrs.timeLockValidator    = address(new TimeLockValidator());
        addrs.biometricValidator   = address(new BiometricValidator());
        addrs.guardianValidator    = address(new GuardianValidator());
        addrs.emergencyFreeze      = address(new EmergencyFreeze());
        addrs.multiSigUpgradeGuard = address(new MultiSigUpgradeGuard());

        console.log("\n[2/4] User Protection...");
        addrs.poisonedAddressProtection = address(new PoisonedAddressProtection());
        addrs.antiScamScreener          = address(new AntiScamScreener());
        addrs.plainEnglishExecutor      = address(new PlainEnglishExecutor());
        addrs.aiThreatOracle            = address(new AIThreatOracle());
        addrs.deepfakeGuard             = address(new DeepfakeGuard());

        console.log("\n[3/4] UX & Accessibility...");
        addrs.seniorModeValidator = address(new SeniorModeValidator());
        addrs.paymasterManager    = address(new PaymasterManager());

        console.log("\n[4/4] Infrastructure...");
        VaultFactory factory = new VaultFactory(entryPoint);
        addrs.vaultFactory = address(factory);

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

        vm.stopBroadcast();

        console.log("\n====================================================");
        console.log("  DEPLOYMENT COMPLETE");
        console.log("====================================================");
        console.log("  TIMELOCK_VALIDATOR=      ", addrs.timeLockValidator);
        console.log("  BIOMETRIC_VALIDATOR=     ", addrs.biometricValidator);
        console.log("  GUARDIAN_VALIDATOR=      ", addrs.guardianValidator);
        console.log("  EMERGENCY_FREEZE=        ", addrs.emergencyFreeze);
        console.log("  MULTISIG_UPGRADE_GUARD=  ", addrs.multiSigUpgradeGuard);
        console.log("  POISONED_ADDRESS=        ", addrs.poisonedAddressProtection);
        console.log("  ANTI_SCAM_SCREENER=      ", addrs.antiScamScreener);
        console.log("  PLAIN_ENGLISH_EXECUTOR=  ", addrs.plainEnglishExecutor);
        console.log("  AI_THREAT_ORACLE=        ", addrs.aiThreatOracle);
        console.log("  DEEPFAKE_GUARD=          ", addrs.deepfakeGuard);
        console.log("  SENIOR_MODE_VALIDATOR=   ", addrs.seniorModeValidator);
        console.log("  PAYMASTER_MANAGER=       ", addrs.paymasterManager);
        console.log("  VAULT_FACTORY=           ", addrs.vaultFactory);
        console.log("====================================================");
    }
}
