// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

/// @notice Per-call hook run by EthosiHookRouter. `account` is the smart account being acted on.
interface ISubHook {
    function preCheck(address account, address target, uint256 value, bytes calldata callData)
        external
        returns (bytes memory);
}
