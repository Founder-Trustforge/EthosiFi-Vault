// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import "../src/EthosiHookRouter.sol";
import "../src/EthosiBootstrap.sol";
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
import "../src/SeniorModeGuard.sol";
import "../src/VaultFactory.sol";
import {MSAAdvanced} from "erc7579/MSAAdvanced.sol";

contract DeployScript is Script {
    address constant ENTRY_POINT_V07 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    struct Addresses {
        address router;
        address bootstrap;
        address biometricValidator;
        address timeLockValidator;
        address guardianValidator;
        address emergencyFreeze;
        address multiSigUpgradeGuard;
        address poisonedAddressProtection;
        address antiScamScreener;
        address plainEnglishExecutor;
        address aiThreatOracle;
        address deepfakeGuard;
        address seniorModeGuard;
        address accountImplementation;
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

        // The router is the account's single hook slot; policy modules only accept calls from it.
        addrs.router = address(new EthosiHookRouter());
        addrs.bootstrap = address(new EthosiBootstrap());

        console.log("\n[1/3] Core security (authorities)...");
        addrs.biometricValidator = address(new BiometricValidator());
        addrs.timeLockValidator = address(new TimeLockValidator(addrs.biometricValidator, addrs.router, entryPoint));
        addrs.guardianValidator = address(new GuardianValidator(addrs.biometricValidator));

        console.log("\n[2/3] Policy hooks (behind the router)...");
        addrs.emergencyFreeze = address(new EmergencyFreeze(addrs.router));
        addrs.multiSigUpgradeGuard = address(new MultiSigUpgradeGuard(addrs.router));
        addrs.poisonedAddressProtection = address(new PoisonedAddressProtection(addrs.router));
        addrs.antiScamScreener = address(new AntiScamScreener(addrs.router));
        addrs.plainEnglishExecutor = address(new PlainEnglishExecutor(addrs.router));
        addrs.aiThreatOracle = address(new AIThreatOracle(addrs.router));
        addrs.deepfakeGuard = address(new DeepfakeGuard(addrs.router));
        addrs.seniorModeGuard = address(new SeniorModeGuard(addrs.router));

        console.log("\n[3/3] Account implementation + factory...");
        addrs.accountImplementation = address(new MSAAdvanced());
        // Only the audited, tested policy hooks are selectable by users. PlainEnglishExecutor,
        // AIThreatOracle and DeepfakeGuard are deployed for experimentation but NOT allow-listed:
        // their on-chain semantics are not safe to rely on yet (see README).
        address[] memory allowed = new address[](5);
        allowed[0] = addrs.emergencyFreeze;
        allowed[1] = addrs.multiSigUpgradeGuard;
        allowed[2] = addrs.poisonedAddressProtection;
        allowed[3] = addrs.antiScamScreener;
        allowed[4] = addrs.seniorModeGuard;
        addrs.vaultFactory = address(
            new VaultFactory(
                entryPoint,
                addrs.accountImplementation,
                addrs.bootstrap,
                addrs.router,
                addrs.biometricValidator,
                addrs.timeLockValidator,
                addrs.guardianValidator,
                allowed
            )
        );

        vm.stopBroadcast();

        console.log("\n====================================================");
        console.log("  DEPLOYMENT COMPLETE");
        console.log("====================================================");
        console.log("  HOOK_ROUTER=             ", addrs.router);
        console.log("  BOOTSTRAP=               ", addrs.bootstrap);
        console.log("  BIOMETRIC_VALIDATOR=     ", addrs.biometricValidator);
        console.log("  TIMELOCK_VALIDATOR=      ", addrs.timeLockValidator);
        console.log("  GUARDIAN_VALIDATOR=      ", addrs.guardianValidator);
        console.log("  EMERGENCY_FREEZE=        ", addrs.emergencyFreeze);
        console.log("  MULTISIG_UPGRADE_GUARD=  ", addrs.multiSigUpgradeGuard);
        console.log("  POISONED_ADDRESS=        ", addrs.poisonedAddressProtection);
        console.log("  ANTI_SCAM_SCREENER=      ", addrs.antiScamScreener);
        console.log("  PLAIN_ENGLISH_EXECUTOR=  ", addrs.plainEnglishExecutor);
        console.log("  AI_THREAT_ORACLE=        ", addrs.aiThreatOracle);
        console.log("  DEEPFAKE_GUARD=          ", addrs.deepfakeGuard);
        console.log("  SENIOR_MODE_GUARD=       ", addrs.seniorModeGuard);
        console.log("  ACCOUNT_IMPLEMENTATION=  ", addrs.accountImplementation);
        console.log("  VAULT_FACTORY=           ", addrs.vaultFactory);
        console.log("====================================================");
    }
}
