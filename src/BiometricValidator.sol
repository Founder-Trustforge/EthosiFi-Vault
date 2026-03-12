// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

<<<<<<< HEAD
import {IValidator} from "erc7579/interfaces/IModule.sol";
=======
import {IERC7579Validator} from "erc7579/interfaces/IERC7579Module.sol";
>>>>>>> origin/main
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/**
 * @title BiometricValidator
 * @notice EthosiFi Vault - WebAuthn/FIDO2 signature verification
 */
<<<<<<< HEAD
contract BiometricValidator is IValidator {
=======
contract BiometricValidator is IERC7579Validator {
>>>>>>> origin/main
    
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
    
<<<<<<< HEAD
    function onInstall(bytes calldata data) external {
=======
    function onInstall(bytes calldata data) external override {
>>>>>>> origin/main
        require(!initialized[msg.sender], "Already initialized");
        
        (bytes32 credentialId, uint256[2] memory pubKey) = abi.decode(data, (bytes32, uint256[2]));
        
        credentialIds[msg.sender] = credentialId;
        publicKeys[credentialId] = pubKey;
        initialized[msg.sender] = true;
        
        emit CredentialRegistered(msg.sender, credentialId);
    }
    
<<<<<<< HEAD
    function onUninstall(bytes calldata) external {
=======
    function onUninstall(bytes calldata) external override {
>>>>>>> origin/main
        delete credentialIds[msg.sender];
        delete publicKeys[credentialIds[msg.sender]];
        initialized[msg.sender] = false;
    }
    
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256
<<<<<<< HEAD
    ) external returns (uint256) {
=======
    ) external view override returns (uint256 validationData) {
>>>>>>> origin/main
        require(initialized[msg.sender], "Not initialized");
        
        bytes32 credId = credentialIds[msg.sender];
        require(credId != bytes32(0), "No credential");
        
        WebAuthnSignature memory sig = abi.decode(userOp.signature, (WebAuthnSignature));
        
        bool valid = _verifyWebAuthn(sig, publicKeys[credId], userOpHash);
        
        return valid ? 0 : 1;
    }
    
    function _verifyWebAuthn(
        WebAuthnSignature memory sig,
        uint256[2] memory pubKey,
        bytes32 hash
    ) internal pure returns (bool) {
        // Production: Use P256Verifier precompile (EIP-7212) or FreshCryptoLib
        // Testnet: Mock verification
        return true;
    }
    
<<<<<<< HEAD
    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == 1;
    }
    
    function isInitialized(address account) external view returns (bool) {
        return initialized[account];
    }

    function validateUserOp(PackedUserOperation calldata, bytes32) external override returns (uint256) {
        return 0;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure override returns (bytes4) {
        return 0xffffffff;
    }

}
=======
    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == 1;
    }
    
    function isInitialized(address account) external view override returns (bool) {
        return initialized[account];
    }
}
>>>>>>> origin/main
