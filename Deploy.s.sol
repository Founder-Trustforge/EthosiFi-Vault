// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import "../src/TimeLockValidator.sol";
import "../src/BiometricValidator.sol";
import "../src/GuardianValidator.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        
        TimeLockValidator timeLock = new TimeLockValidator();
        BiometricValidator biometric = new BiometricValidator();
        GuardianValidator guardian = new GuardianValidator();
        
        console.log("TimeLockValidator:", address(timeLock));
        console.log("BiometricValidator:", address(biometric));
        console.log("GuardianValidator:", address(guardian));
        
        vm.stopBroadcast();
    }
}
