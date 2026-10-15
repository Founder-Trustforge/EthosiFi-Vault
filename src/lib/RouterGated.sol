// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

/// @notice Sub-hooks only accept `preCheck` from the account's EthosiHookRouter, which in turn
/// is only ever called by the account itself. This stops anyone from calling a sub-hook's
/// preCheck directly to mutate or burn another account's per-account state.
abstract contract RouterGated {
    address public immutable ROUTER;

    error NotRouter();
    error ZeroRouter();

    constructor(address router_) {
        if (router_ == address(0)) revert ZeroRouter();
        ROUTER = router_;
    }

    modifier onlyRouter() {
        if (msg.sender != ROUTER) revert NotRouter();
        _;
    }
}
