// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;
interface ITL { function confirmAndRelease(address account, bytes32 txHash, bytes calldata sig) external; }
contract Reenter {
    ITL public tl; address public acct; bytes32 public txHash; bytes public sig; uint256 public hits; bool public reentered; bool public reenterOk;
    function arm(address t, address a, bytes32 h, bytes calldata s) external { tl = ITL(t); acct = a; txHash = h; sig = s; }
    receive() external payable {
        hits++;
        if (!reentered) {
            reentered = true;
            try tl.confirmAndRelease(acct, txHash, sig) { reenterOk = true; } catch { reenterOk = false; }
        }
    }
}
