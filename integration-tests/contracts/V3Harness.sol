// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;
import {V3Math} from "../src/lib/V3Math.sol";
contract V3Harness {
    function sqrtAt(int24 t) external pure returns (uint160) { return V3Math.getSqrtRatioAtTick(t); }
    function amounts(uint160 p, uint160 a, uint160 b, uint128 l) external pure returns (uint256, uint256) { return V3Math.getAmountsForLiquidity(p, a, b, l); }
}
contract GovTarget {
    uint256 public pings; function ping() external { pings++; }
}
