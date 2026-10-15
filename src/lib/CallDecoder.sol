// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

/// @notice Fail-closed decoding of ERC-7579 account calls, shared by the validators
/// (userOp.callData) and the hook router (msg.data).
library CallDecoder {
    bytes4 internal constant EXECUTE = 0xe9ae5c53; // execute(bytes32,bytes)
    bytes4 internal constant ERC20_TRANSFER = 0xa9059cbb; // transfer(address,uint256)

    uint8 internal constant CALLTYPE_SINGLE = 0x00;
    uint8 internal constant CALLTYPE_BATCH = 0x01;

    /// @dev Result of classifying a single call.
    /// kind: 0 = unknown/other (fail closed), 1 = native send, 2 = ERC-20 transfer
    struct Transfer {
        uint8 kind;
        address token; // address(0) for native
        address recipient;
        uint256 amount;
    }

    /// @notice Decode `execute(bytes32 mode, bytes executionCalldata)` calldata that is a
    /// SINGLE call (anything else returns ok=false).
    function decodeExecuteSingle(bytes calldata callData)
        internal
        pure
        returns (bool ok, address target, uint256 value, bytes calldata data)
    {
        if (callData.length < 4 + 64 || bytes4(callData[:4]) != EXECUTE) {
            return (false, address(0), 0, callData[0:0]);
        }
        bytes32 mode = bytes32(callData[4:36]);
        if (uint8(bytes1(mode)) != CALLTYPE_SINGLE) return (false, address(0), 0, callData[0:0]);
        uint256 off = uint256(bytes32(callData[36:68]));
        // canonical ABI only: the dynamic `bytes` must start right after the 2 head words
        if (off != 0x40) return (false, address(0), 0, callData[0:0]);
        if (callData.length < 4 + 0x40 + 32) return (false, address(0), 0, callData[0:0]);
        uint256 len = uint256(bytes32(callData[68:100]));
        if (len < 52 || len > callData.length || 100 + len > callData.length) {
            return (false, address(0), 0, callData[0:0]);
        }
        bytes calldata ec = callData[100:100 + len];
        target = address(bytes20(ec[0:20]));
        value = uint256(bytes32(ec[20:52]));
        data = ec[52:];
        ok = true;
    }

    /// @notice Classify a (target, value, data) call as native send / ERC-20 transfer / other.
    function classify(address target, uint256 value, bytes calldata data) internal pure returns (Transfer memory t) {
        if (data.length == 0) {
            t = Transfer(1, address(0), target, value);
        } else if (value == 0 && data.length == 68 && bytes4(data[:4]) == ERC20_TRANSFER) {
            // exact transfer(address,uint256) encoding, no trailing bytes, value must be 0
            t = Transfer(2, target, address(uint160(uint256(bytes32(data[4:36])))), uint256(bytes32(data[36:68])));
            // upper 12 bytes of the address word must be zero (canonical)
            if (uint256(bytes32(data[4:36])) >> 160 != 0) t.kind = 0;
        }
    }

    /// @notice Same classification for memory input (hook router passes memory-decoded calls).
    function classifyMem(address target, uint256 value, bytes memory data) internal pure returns (Transfer memory t) {
        if (data.length == 0) {
            t = Transfer(1, address(0), target, value);
        } else if (value == 0 && data.length == 68) {
            bytes4 sel;
            uint256 a;
            uint256 amt;
            assembly {
                sel := mload(add(data, 32))
                a := mload(add(data, 36))
                amt := mload(add(data, 68))
            }
            if (sel == ERC20_TRANSFER && a >> 160 == 0) {
                t = Transfer(2, target, address(uint160(a)), amt);
            }
        }
    }
}
