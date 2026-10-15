// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;
import {V3Math} from "../src/lib/V3Math.sol";

/// Test double for a Uniswap V3 pool: only what EthosLiquidityManager calls.
contract MockV3Pool {
    address public token0; address public token1; uint24 public fee;
    int56 public twapTick; bool public tooYoung; int24 public spotTick;
    constructor(address a, address b, uint24 f, int24 t) { token0 = a; token1 = b; fee = f; twapTick = t; spotTick = t; }
    function setTwap(int24 t) external { twapTick = t; }
    function setSpot(int24 t) external { spotTick = t; }
    function setTooYoung(bool v) external { tooYoung = v; }
    function slot0() external view returns (uint160, int24, uint16, uint16, uint16, uint8, bool) {
        return (V3Math.getSqrtRatioAtTick(spotTick), spotTick, 0, 0, 0, 0, true);
    }
    function liquidity() external pure returns (uint128) { return 1; }
    function observe(uint32[] calldata ago) external view returns (int56[] memory c, uint160[] memory s) {
        require(!tooYoung, "OLD");
        c = new int56[](2); s = new uint160[](2);
        c[0] = 0; c[1] = twapTick * int56(uint56(ago[0]));
    }
}
contract MockPositionManager {
    struct Position { uint96 nonce; address operator; address token0; address token1; uint24 fee; int24 tickLower; int24 tickUpper; uint128 liquidity; uint256 a; uint256 b; uint128 c; uint128 d; }
    mapping(uint256 => address) public owners; mapping(uint256 => Position) public pos;
    function set(uint256 id, address o, address t0, address t1, uint24 fee, int24 lo, int24 hi, uint128 liq) external {
        owners[id] = o; pos[id] = Position(0, address(0), t0, t1, fee, lo, hi, liq, 0, 0, 0, 0);
    }
    function setOwner(uint256 id, address o) external { owners[id] = o; }
    function setLiquidity(uint256 id, uint128 l) external { pos[id].liquidity = l; }
    function ownerOf(uint256 id) external view returns (address) { require(owners[id] != address(0), "NOT_MINTED"); return owners[id]; }
    function positions(uint256 id) external view returns (Position memory) { return pos[id]; }
}
