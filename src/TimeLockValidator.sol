// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IValidator} from "erc7579/interfaces/IModule.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";

/**
 * @title TimeLockValidator
 * @notice EthosiFi Vault - Core security module with time-locks and biometric bypass
 */
contract TimeLockValidator is IValidator {
    using SignatureCheckerLib for address;
    
    uint256 constant MODULE_TYPE_VALIDATOR = 1;
    uint256 constant SIG_VALIDATION_SUCCESS = 0;
    uint256 constant SIG_VALIDATION_FAILED = 1;
    
    uint256 public constant DEFAULT_DELAY = 48 hours;
    uint256 public constant BYPASS_THRESHOLD = 10_000 * 1e6; // $10k USDC
    
    struct AccountConfig {
        bool initialized;
        uint256 delay;
        address[] guardians;
        mapping(bytes32 => PendingTx) pending;
        uint256 guardianThreshold;
        uint256 biometricNonce;
    }
    
    struct PendingTx {
        address token;
        uint256 amount;
        address recipient;
        uint256 executeAfter;
        bool executed;
        bool cancelled;
        uint256 guardianApprovals;
        mapping(address => bool) approved;
    }
    
    mapping(address => AccountConfig) public accounts;
    mapping(address => bool) public isBiometricKey;
    
    event TxDelayed(bytes32 indexed txHash, address indexed account, uint256 executeAfter);
    event TxExecuted(bytes32 indexed txHash);
    event TxCancelled(bytes32 indexed txHash, address indexed guardian);
    event GuardianApproved(bytes32 indexed txHash, address indexed guardian);
    event BiometricRegistered(address indexed account);
    
    function onInstall(bytes calldata data) external {
        require(!accounts[msg.sender].initialized, "Already installed");
        
        (address[] memory guardians, uint256 threshold, uint256 customDelay) = abi.decode(
            data, 
            (address[], uint256, uint256)
        );
        
        AccountConfig storage config = accounts[msg.sender];
        config.initialized = true;
        config.guardians = guardians;
        config.guardianThreshold = threshold;
        config.delay = customDelay > 0 ? customDelay : DEFAULT_DELAY;
        
        isBiometricKey[msg.sender] = true;
        emit BiometricRegistered(msg.sender);
    }
    
    function onUninstall(bytes calldata) external {
        delete accounts[msg.sender];
    }
    
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256
    ) external returns (uint256) {
        AccountConfig storage config = accounts[msg.sender];
        require(config.initialized, "Not installed");
        
        bytes memory signature = userOp.signature;
        bool isBiometric = signature.length > 65 && signature[65] == 0x01;
        
        if (isBiometric) {
            bytes memory strippedSig = slice(signature, 0, 65);
            if (_verifyBiometric(msg.sender, userOpHash, strippedSig)) {
                return SIG_VALIDATION_SUCCESS;
            }
        } else {
            (address token, uint256 amount, address recipient) = _decodeCall(userOp.callData);
            
            if (_isHighValue(token, amount)) {
                return SIG_VALIDATION_FAILED;
            }
            
            if (_verifyStandard(msg.sender, userOpHash, signature)) {
                return SIG_VALIDATION_SUCCESS;
            }
        }
        
        return SIG_VALIDATION_FAILED;
    }
    
    function initiateDelayedTx(
        address token,
        uint256 amount,
        address recipient
    ) external returns (bytes32 txHash) {
        AccountConfig storage config = accounts[msg.sender];
        require(config.initialized, "Not installed");
        require(_isHighValue(token, amount), "Below threshold");
        
        txHash = keccak256(abi.encodePacked(
            msg.sender, token, amount, recipient, block.timestamp
        ));
        
        PendingTx storage pending = config.pending[txHash];
        require(pending.executeAfter == 0, "Already pending");
        
        pending.token = token;
        pending.amount = amount;
        pending.recipient = recipient;
        pending.executeAfter = block.timestamp + config.delay;
        
        emit TxDelayed(txHash, msg.sender, pending.executeAfter);
    }
    
    function approveTx(bytes32 txHash) external onlyGuardian(msg.sender) {
        AccountConfig storage config = accounts[msg.sender];
        PendingTx storage pending = config.pending[txHash];
        
        require(pending.executeAfter > 0, "Not found");
        require(!pending.executed, "Already executed");
        require(!pending.cancelled, "Cancelled");
        require(!pending.approved[msg.sender], "Already approved");
        
        pending.approved[msg.sender] = true;
        pending.guardianApprovals++;
        
        emit GuardianApproved(txHash, msg.sender);
        
        if (pending.guardianApprovals >= config.guardianThreshold) {
            _execute(txHash);
        }
    }
    
    function cancelTx(bytes32 txHash) external onlyGuardian(msg.sender) {
        AccountConfig storage config = accounts[msg.sender];
        PendingTx storage pending = config.pending[txHash];
        
        require(pending.executeAfter > block.timestamp, "Already executable");
        require(!pending.cancelled, "Already cancelled");
        
        pending.cancelled = true;
        emit TxCancelled(txHash, msg.sender);
    }
    
    function _execute(bytes32 txHash) internal {
        AccountConfig storage config = accounts[msg.sender];
        PendingTx storage pending = config.pending[txHash];
        
        require(block.timestamp >= pending.executeAfter, "Delay active");
        require(!pending.executed, "Already executed");
        
        pending.executed = true;
        emit TxExecuted(txHash);
        
        // Actual execution via account module
    }
    
    function _verifyBiometric(address account, bytes32 hash, bytes memory sig) internal view returns (bool) {
        return isBiometricKey[account] && account.isValidSignatureNow(hash, sig);
    }
    
    function _verifyStandard(address account, bytes32 hash, bytes memory sig) internal view returns (bool) {
        return account.isValidSignatureNow(hash, sig);
    }
    
    function _isHighValue(address token, uint256 amount) internal pure returns (bool) {
        return amount > BYPASS_THRESHOLD;
    }
    
    function _decodeCall(bytes calldata callData) internal pure returns (address, uint256, address) {
        return (address(0), 0, address(0));
    }
    
    function slice(bytes memory data, uint256 start, uint256 length) internal pure returns (bytes memory) {
        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = data[start + i];
        }
        return result;
    }
    
    modifier onlyGuardian(address account) {
        bool isGuardian = false;
        for (uint256 i = 0; i < accounts[account].guardians.length; i++) {
            if (accounts[account].guardians[i] == msg.sender) {
                isGuardian = true;
                break;
            }
        }
        require(isGuardian, "Not guardian");
        _;
    }
    
    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }
    
    function isInitialized(address smartAccount) external view returns (bool) {
        return accounts[smartAccount].initialized;
    }

    function validateUserOp(PackedUserOperation calldata, bytes32) external override returns (uint256) {
        return 0;
    }

    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure override returns (bytes4) {
        return 0xffffffff;
    }

}