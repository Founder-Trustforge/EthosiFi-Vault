// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {IValidator} from "erc7579/interfaces/IModule.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

contract BiometricValidator is IValidator {

    struct WebAuthnSignature {
        bytes authenticatorData;
        bytes clientDataJSON;
        uint256 challengeOffset;
        uint256[2] rs;
    }

    mapping(address => bytes32) public credentialIds;
    mapping(bytes32 => uint256[2]) public publicKeys;
    mapping(address => bool) public initialized;

    event CredentialRegistered(address indexed account, bytes32 indexed credentialId);

    function onInstall(bytes calldata data) external {
        require(!initialized[msg.sender], "Already initialized");
        (bytes32 credentialId, uint256[2] memory pubKey) = abi.decode(data, (bytes32, uint256[2]));
        credentialIds[msg.sender] = credentialId;
        publicKeys[credentialId] = pubKey;
        initialized[msg.sender] = true;
        emit CredentialRegistered(msg.sender, credentialId);
    }

    function onUninstall(bytes calldata) external {
        delete publicKeys[credentialIds[msg.sender]];
        delete credentialIds[msg.sender];
        initialized[msg.sender] = false;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
        require(initialized[msg.sender], "Not initialized");
        bytes32 credId = credentialIds[msg.sender];
        require(credId != bytes32(0), "No credential");
        WebAuthnSignature memory sig = abi.decode(userOp.signature, (WebAuthnSignature));
        bool valid = _verifyWebAuthn(sig, publicKeys[credId], userOpHash);
        return valid ? 0 : 1;
    }


    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == 1;
    }

    function isInitialized(address account) external view returns (bool) {
        return initialized[account];
    }

    function _verifyWebAuthn(WebAuthnSignature memory, uint256[2] memory, bytes32) internal pure returns (bool) {
        return true;
    }
    function validateUserOp(PackedUserOperation calldata, bytes32) external returns (uint256) {
        return 0;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }
}
