// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {V3Math} from "../src/lib/V3Math.sol";

/// Quick Foundry checks of the pure math. The full system (EntryPoint, account, all modules) is
/// covered by the hardhat integration suite in integration-tests/ (see README, "Testing").
contract V3MathTest is Test {
    function test_tickZeroIsOne() public pure {
        assertEq(uint256(V3Math.getSqrtRatioAtTick(0)), 2 ** 96);
    }

    function test_extremeTicksMatchUniswapConstants() public pure {
        assertEq(uint256(V3Math.getSqrtRatioAtTick(-887272)), 4295128739);
        assertEq(uint256(V3Math.getSqrtRatioAtTick(887272)), 1461446703485210103287273052203988822378723970342);
    }

    function test_monotonic(int24 a, int24 b) public pure {
        a = int24(bound(int256(a), -887272, 887271));
        b = int24(bound(int256(b), int256(a) + 1, 887272));
        assertLt(uint256(V3Math.getSqrtRatioAtTick(a)), uint256(V3Math.getSqrtRatioAtTick(b)) + 1);
    }

    function test_fullRangeLiquidityHoldsBothTokens() public pure {
        uint160 p = V3Math.getSqrtRatioAtTick(0);
        (uint256 a0, uint256 a1) = V3Math.getAmountsForLiquidity(
            p, V3Math.getSqrtRatioAtTick(-887272), V3Math.getSqrtRatioAtTick(887272), 1e18
        );
        assertGt(a0, 0);
        assertGt(a1, 0);
    }
}
