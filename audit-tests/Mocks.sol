// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;
import {TimeLockValidator} from "src/TimeLockValidator.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
contract MockToken {
    mapping(address => uint256) public balanceOf;
    function mint(address a, uint256 v) external { balanceOf[a] += v; }
    function transfer(address to, uint256 v) external returns (bool) { balanceOf[msg.sender] -= v; balanceOf[to] += v; return true; }
}
contract MockBio {
    bool public ok = true;
    function set(bool b) external { ok = b; }
    function verifyConfirmation(address, bytes32, bytes calldata) external view returns (bool) { return ok; }
}
contract MockAccount {
    address public executor;
    event V(uint256 r);
    receive() external payable {}
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) { return 0x1626ba7e; }
    function setExecutor(address e) external { executor = e; }
    function call(address t, bytes calldata d) external returns (bytes memory) {
        (bool ok, bytes memory r) = t.call(d);
        if (!ok) { assembly { revert(add(r, 32), mload(r)) } }
        return r;
    }
    function validate(TimeLockValidator m, PackedUserOperation calldata op, bytes32 h) external returns (uint256 r) {
        r = m.validateUserOp(op, h);
        emit V(r);
    }
    function executeFromExecutor(bytes32, bytes calldata ec) external returns (bytes[] memory) {
        require(msg.sender == executor, "not executor");
        address t = address(bytes20(ec[0:20]));
        uint256 v = uint256(bytes32(ec[20:52]));
        (bool ok,) = t.call{value: v}(ec[52:]);
        require(ok, "exec failed");
        return new bytes[](0);
    }
}
