// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import "forge-std/Script.sol";
import {EthosToken} from "../src/EthosToken.sol";
import {EthosMVPBadge} from "../src/EthosMVPBadge.sol";
import {EthosStaking} from "../src/EthosStaking.sol";
import {EthosGovernance} from "../src/EthosGovernance.sol";
import {EthosLiquidityManager} from "../src/EthosLiquidityManager.sol";

/// @notice Deploys and wires the $ETHOS token suite. Run separately from the Vault (Deploy.s.sol).
/// Required env: PRIVATE_KEY, TREASURY, ECOSYSTEM, EARLY_CONTRIBUTORS, PUBLIC_LAUNCH, TEAM_VESTING
/// Optional env (only when the Uniswap V3 ETHOS/USDC pool already exists): POSITION_MANAGER, ETHOS_USDC_POOL, USDC
/// After deployment, move every `owner` to a multisig with transferOwnership + acceptOwnership.
contract DeployTokenScript is Script {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        EthosToken token = new EthosToken(
            vm.envAddress("TREASURY"),
            vm.envAddress("ECOSYSTEM"),
            vm.envAddress("EARLY_CONTRIBUTORS"),
            vm.envAddress("PUBLIC_LAUNCH"),
            vm.envAddress("TEAM_VESTING")
        );
        EthosMVPBadge badge = new EthosMVPBadge();
        EthosStaking staking = new EthosStaking(address(token));
        EthosGovernance gov = new EthosGovernance(address(staking));
        EthosLiquidityManager lpm = new EthosLiquidityManager(address(token));

        // Wiring: staking + LP manager may burn (their own balance / with the holder's allowance) and mint tiers.
        token.setContracts(address(staking), address(0), address(lpm));
        badge.authorizeMinter(address(staking));
        badge.authorizeMinter(address(lpm));
        staking.setMVPBadge(address(badge));
        staking.setGovernanceContract(address(gov));
        lpm.setMVPBadge(address(badge));

        address pm = vm.envOr("POSITION_MANAGER", address(0));
        address pool = vm.envOr("ETHOS_USDC_POOL", address(0));
        address usdc = vm.envOr("USDC", address(0));
        if (pm != address(0) && pool != address(0) && usdc != address(0)) {
            lpm.configurePool(pm, pool, address(token), usdc);
        } else {
            console.log("LP pool NOT configured: call configurePool once the ETHOS/USDC pool exists.");
        }

        vm.stopBroadcast();

        console.log("ETHOS_TOKEN=            ", address(token));
        console.log("MVP_BADGE=              ", address(badge));
        console.log("STAKING=                ", address(staking));
        console.log("GOVERNANCE=             ", address(gov));
        console.log("LIQUIDITY_MANAGER=      ", address(lpm));
    }
}
