// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IValidator} from "erc7579/interfaces/IModule.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/**
 * @title GuardianValidator
 * @notice EthosiFi Vault - Social recovery with time delays
 */
contract GuardianValidator is IValidator {
    
    struct Guardian {
        address addr;
        uint256 weight;
        bytes32 identityHash;
        uint256 lastApproval;
    }
    
    struct RecoveryRequest {
        bytes32 newCredentialHash;
        uint256 initiatedAt;
        uint256 totalWeight;
        bool executed;
        mapping(address => bool) approved;
    }
    
    mapping(address => Guardian[]) public guardians;
    mapping(address => uint256) public threshold;
    mapping(address => RecoveryRequest) public recoveries;
    mapping(address => bool) public initialized;
    
    uint256 public constant RECOVERY_DELAY = 48 hours;
    uint256 public constant APPROVAL_COOLDOWN = 6 hours;
    
    event RecoveryInitiated(address indexed account, bytes32 indexed newCredential);
    event GuardianApproved(address indexed account, address indexed guardian);
    event RecoveryExecuted(address indexed account);
    
    function onInstall(bytes calldata data) external {
        require(!initialized[msg.sender], "Already initialized");
        
        (Guardian[] memory _guardians, uint256 _threshold) = abi.decode(data, (Guardian[], uint256));
        
        for (uint256 i = 0; i < _guardians.length; i++) {
            guardians[msg.sender].push(_guardians[i]);
        }
        
        threshold[msg.sender] = _threshold;
        initialized[msg.sender] = true;
    }
    
    function onUninstall(bytes calldata) external {
        delete guardians[msg.sender];
        delete threshold[msg.sender];
        initialized[msg.sender] = false;
    }
    
    function initiateRecovery(bytes32 newCredentialHash) external {
        require(initialized[msg.sender], "Not initialized");
        
        RecoveryRequest storage req = recoveries[msg.sender];
        require(req.initiatedAt == 0, "Recovery pending");
        
        req.newCredentialHash = newCredentialHash;
        req.initiatedAt = block.timestamp;
        
        emit RecoveryInitiated(msg.sender, newCredentialHash);
    }
    
    function approveRecovery(address account) external onlyGuardian(account) {
        RecoveryRequest storage req = recoveries[account];
        require(req.initiatedAt > 0, "No recovery");
        require(!req.executed, "Already executed");
        require(!req.approved[msg.sender], "Already approved");
        require(
            block.timestamp > _getGuardian(account, msg.sender).lastApproval + APPROVAL_COOLDOWN,
            "Cooldown active"
        );
        
        Guardian storage g = _getGuardian(account, msg.sender);
        g.lastApproval = block.timestamp;
        req.approved[msg.sender] = true;
        req.totalWeight += g.weight;
        
        emit GuardianApproved(account, msg.sender);
        
        if (req.totalWeight >= threshold[account] && 
            block.timestamp >= req.initiatedAt + RECOVERY_DELAY) {
            _executeRecovery(account);
        }
    }
    
    function _executeRecovery(address account) internal {
        RecoveryRequest storage req = recoveries[account];
        req.executed = true;
        
        // Rotate credential via account module
        emit RecoveryExecuted(account);
    }
    
    function _getGuardian(address account, address addr) internal view returns (Guardian storage) {
        for (uint256 i = 0; i < guardians[account].length; i++) {
            if (guardians[account][i].addr == addr) {
                return guardians[account][i];
            }
        }
        revert("Not guardian");
    }
    
    modifier onlyGuardian(address account) {
        bool isGuardian = false;
        for (uint256 i = 0; i < guardians[account].length; i++) {
            if (guardians[account][i].addr == msg.sender) {
                isGuardian = true;
                break;
            }
        }
        require(isGuardian, "Not guardian");
        _;
    }
    
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external pure returns (uint256) {
        return 1; // This validator doesn't validate userOps directly
    }
    
    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == 1;
    }
    
    function isInitialized(address account) external view returns (bool) {
        return initialized[account];
    }
    function validateUserOp(PackedUserOperation calldata, bytes32) external returns (uint256) {
        return 0;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }
}
