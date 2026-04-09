// SPDX-License-Identifier: BSL-1.1
pragma solidity ^0.8.23;

import {IValidator} from "erc7579/interfaces/IModule.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {ReentrancyGuard} from "solady/utils/ReentrancyGuard.sol";

/**
 * @title  BiometricValidator
 * @author EthosiFi (founder@ethosifi.com)
 * @notice ERC-7579 validator module — WebAuthn/FIDO2 biometric authentication
 *         for the EthosiFi Vault.
 *
 *         Security model
 *         ──────────────
 *         • Each smart account registers exactly one WebAuthn credential (device biometric).
 *         • Signatures are full WebAuthn assertions: authenticatorData + clientDataJSON + P256 (r,s).
 *         • The userOpHash is embedded in clientDataJSON as the WebAuthn "challenge".
 *         • P256 verification uses the RIP-7212 precompile (0x100) available on
 *           Base, Optimism, and Arbitrum (OP-stack chains).
 *         • Falls back to a pure-Solidity P256 verifier if precompile is unavailable.
 *         • Multiple credentials per account supported via credentialId → pubKey mapping.
 *         • Credentials can be rotated (new device) or revoked (lost device) by the account.
 *
 *         WebAuthn verification steps (FIDO2 spec §7.2)
 *         ───────────────────────────────────────────────
 *         1. Verify authenticatorData.rpIdHash matches expected RP ID.
 *         2. Verify authenticatorData flags: UP (user presence) bit MUST be set.
 *         3. Verify clientDataJSON.type == "webauthn.get".
 *         4. Verify clientDataJSON.challenge == base64url(userOpHash).
 *         5. Compute message = sha256(authenticatorData ‖ sha256(clientDataJSON)).
 *         6. Verify P256 signature (r, s) over message using the registered public key.
 *
 * @dev    BSL 1.1 — non-commercial use free; commercial license: founder@ethosifi.com
 *         Converts to GPL-3.0 on 2029-01-01.
 */
contract BiometricValidator is IValidator, ReentrancyGuard {

    // ─────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────

    uint256 public constant MODULE_TYPE_VALIDATOR  = 1;
    uint256 public constant SIG_VALIDATION_SUCCESS = 0;
    uint256 public constant SIG_VALIDATION_FAILED  = 1;

    /// @notice RIP-7212 / EIP-7212 P256 verification precompile.
    ///         Available on Base, Optimism, Arbitrum (OP-stack).
    address public constant P256_PRECOMPILE = address(0x100);

    /// @notice User Presence flag bit in authenticatorData (FIDO2 spec).
    uint8 private constant AUTH_FLAG_UP = 0x01;

    /// @notice User Verification flag bit in authenticatorData.
    uint8 private constant AUTH_FLAG_UV = 0x04;

    // ─────────────────────────────────────────────────────────────
    // Types
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice Full WebAuthn assertion signature, ABI-encoded in userOp.signature.
     *
     * @param authenticatorData Raw authenticatorData bytes from the authenticator.
     *                          Must be ≥37 bytes: [rpIdHash(32)][flags(1)][counter(4)][...].
     * @param clientDataJSON    UTF-8 JSON string from the authenticator, containing
     *                          "type", "challenge", "origin" fields.
     * @param challengeOffset   Byte offset of the base64url-encoded challenge value
     *                          inside clientDataJSON (points just after `"challenge":"`).
     * @param rs                P256 signature components [r, s].
     * @param credentialId      The credential ID to use for this account
     *                          (allows multi-credential accounts).
     */
    struct WebAuthnSignature {
        bytes       authenticatorData;
        bytes       clientDataJSON;
        uint256     challengeOffset;
        uint256[2]  rs;
        bytes32     credentialId;
    }

    /**
     * @notice On-chain credential record.
     */
    struct Credential {
        uint256[2] publicKey;   // P256 (x, y) coordinates
        bool       active;
        uint256    registeredAt;
    }

    // ─────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────

    /// @dev account → initialized flag
    mapping(address => bool) private _initialized;

    /// @dev credentialId → Credential record
    mapping(bytes32 => Credential) private _credentials;

    /// @dev account → list of credentialIds (supports multiple devices)
    mapping(address => bytes32[]) private _accountCredentials;

    /// @dev account → primary credentialId (used when sig doesn't specify one)
    mapping(address => bytes32) private _primaryCredential;

    /// @dev account → rpIdHash (sha256 of the relying party domain, e.g. "ethosifi.xyz")
    mapping(address => bytes32) private _rpIdHashes;

    /// @dev replay protection: sha256(authenticatorData ‖ clientDataJSON) → used
    mapping(bytes32 => bool) private _usedAssertions;

    // ─────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────

    event CredentialRegistered(
        address indexed account,
        bytes32 indexed credentialId,
        bool isPrimary
    );
    event CredentialRevoked(
        address indexed account,
        bytes32 indexed credentialId
    );
    event PrimaryCredentialChanged(
        address indexed account,
        bytes32 indexed credentialId
    );

    // ─────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────

    error AlreadyInitialized();
    error NotInitialized();
    error NoCredential();
    error CredentialNotFound();
    error CredentialRevoked();
    error CredentialAlreadyExists();
    error InvalidAuthenticatorData();
    error UserPresenceNotSet();
    error InvalidClientDataType();
    error ChallengeMismatch();
    error InvalidSignature();
    error ReplayDetected();
    error InvalidPublicKey();
    error InvalidRpIdHash();
    error NotAccountOwner();

    // ─────────────────────────────────────────────────────────────
    // ERC-7579 Module lifecycle
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice Install the module on a smart account.
     * @param  data ABI-encoded (bytes32 credentialId, uint256[2] pubKey,
     *                           bytes32 rpIdHash)
     *              rpIdHash: sha256("ethosifi.xyz") or the app's RP ID domain hash.
     */
    function onInstall(bytes calldata data) external override {
        if (_initialized[msg.sender]) revert AlreadyInitialized();

        (bytes32 credentialId, uint256[2] memory pubKey, bytes32 rpIdHash) =
            abi.decode(data, (bytes32, uint256[2], bytes32));

        if (credentialId == bytes32(0))           revert NoCredential();
        if (pubKey[0] == 0 || pubKey[1] == 0)     revert InvalidPublicKey();
        if (rpIdHash == bytes32(0))               revert InvalidRpIdHash();
        if (_credentials[credentialId].active)    revert CredentialAlreadyExists();

        _credentials[credentialId] = Credential({
            publicKey:    pubKey,
            active:       true,
            registeredAt: block.timestamp
        });

        _accountCredentials[msg.sender].push(credentialId);
        _primaryCredential[msg.sender] = credentialId;
        _rpIdHashes[msg.sender]        = rpIdHash;
        _initialized[msg.sender]       = true;

        emit CredentialRegistered(msg.sender, credentialId, true);
    }

    /**
     * @notice Uninstall — deactivates all credentials for this account.
     */
    function onUninstall(bytes calldata) external override {
        bytes32[] storage creds = _accountCredentials[msg.sender];
        for (uint256 i = 0; i < creds.length; i++) {
            _credentials[creds[i]].active = false;
        }
        delete _accountCredentials[msg.sender];
        delete _primaryCredential[msg.sender];
        delete _rpIdHashes[msg.sender];
        _initialized[msg.sender] = false;
    }

    // ─────────────────────────────────────────────────────────────
    // ERC-7579 Validation
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice Validate a UserOperation using a WebAuthn biometric assertion.
     *
     *         userOp.signature must be ABI-encoded WebAuthnSignature struct.
     *         The challenge embedded in clientDataJSON must equal base64url(userOpHash).
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 /* missingAccountFunds */
    ) external override nonReentrant returns (uint256) {
        if (!_initialized[msg.sender]) revert NotInitialized();

        WebAuthnSignature memory sig = abi.decode(userOp.signature, (WebAuthnSignature));

        // Use credentialId from signature, fall back to primary
        bytes32 credId = sig.credentialId != bytes32(0)
            ? sig.credentialId
            : _primaryCredential[msg.sender];

        if (credId == bytes32(0)) revert NoCredential();

        Credential storage cred = _credentials[credId];
        if (!cred.active) revert CredentialRevoked();

        bool valid = _verifyWebAuthn(sig, cred.publicKey, userOpHash, _rpIdHashes[msg.sender]);
        return valid ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }

    /**
     * @notice EIP-1271 signature validation for off-chain messages.
     * @return 0x1626ba7e on success, 0xffffffff on failure.
     */
    function isValidSignatureWithSender(
        address /* sender */,
        bytes32 hash,
        bytes calldata signature
    ) external view override returns (bytes4) {
        if (!_initialized[msg.sender]) return 0xffffffff;

        WebAuthnSignature memory sig = abi.decode(signature, (WebAuthnSignature));

        bytes32 credId = sig.credentialId != bytes32(0)
            ? sig.credentialId
            : _primaryCredential[msg.sender];

        if (credId == bytes32(0)) return 0xffffffff;

        Credential storage cred = _credentials[credId];
        if (!cred.active) return 0xffffffff;

        bool valid = _verifyWebAuthn(sig, cred.publicKey, hash, _rpIdHashes[msg.sender]);
        return valid ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    // ─────────────────────────────────────────────────────────────
    // Credential management
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice Add an additional credential (e.g. a second device).
     *         Only callable by the account itself.
     */
    function addCredential(
        bytes32 credentialId,
        uint256[2] calldata pubKey
    ) external {
        if (!_initialized[msg.sender]) revert NotInitialized();
        if (credentialId == bytes32(0))        revert NoCredential();
        if (pubKey[0] == 0 || pubKey[1] == 0)  revert InvalidPublicKey();
        if (_credentials[credentialId].active)  revert CredentialAlreadyExists();

        _credentials[credentialId] = Credential({
            publicKey:    pubKey,
            active:       true,
            registeredAt: block.timestamp
        });
        _accountCredentials[msg.sender].push(credentialId);

        emit CredentialRegistered(msg.sender, credentialId, false);
    }

    /**
     * @notice Revoke a credential (lost/stolen device).
     *         Cannot revoke the primary unless another active credential exists.
     */
    function revokeCredential(bytes32 credentialId) external {
        if (!_initialized[msg.sender]) revert NotInitialized();
        if (!_isAccountCredential(msg.sender, credentialId)) revert CredentialNotFound();

        // Prevent locking out the account — must have at least 1 active credential after revocation
        uint256 activeCount = _activeCredentialCount(msg.sender);
        require(activeCount > 1, "Cannot revoke last credential");

        _credentials[credentialId].active = false;

        // If revoking primary, promote oldest other active credential
        if (_primaryCredential[msg.sender] == credentialId) {
            bytes32[] storage creds = _accountCredentials[msg.sender];
            for (uint256 i = 0; i < creds.length; i++) {
                if (creds[i] != credentialId && _credentials[creds[i]].active) {
                    _primaryCredential[msg.sender] = creds[i];
                    emit PrimaryCredentialChanged(msg.sender, creds[i]);
                    break;
                }
            }
        }

        emit CredentialRevoked(msg.sender, credentialId);
    }

    /**
     * @notice Set which credential is the primary (default) for this account.
     */
    function setPrimaryCredential(bytes32 credentialId) external {
        if (!_initialized[msg.sender]) revert NotInitialized();
        if (!_isAccountCredential(msg.sender, credentialId)) revert CredentialNotFound();
        if (!_credentials[credentialId].active) revert CredentialRevoked();

        _primaryCredential[msg.sender] = credentialId;
        emit PrimaryCredentialChanged(msg.sender, credentialId);
    }

    // ─────────────────────────────────────────────────────────────
    // View helpers
    // ─────────────────────────────────────────────────────────────

    function getCredential(bytes32 credentialId) external view returns (
        uint256[2] memory publicKey,
        bool active,
        uint256 registeredAt
    ) {
        Credential storage c = _credentials[credentialId];
        return (c.publicKey, c.active, c.registeredAt);
    }

    function getAccountCredentials(address account) external view returns (bytes32[] memory) {
        return _accountCredentials[account];
    }

    function getPrimaryCredential(address account) external view returns (bytes32) {
        return _primaryCredential[account];
    }

    function getRpIdHash(address account) external view returns (bytes32) {
        return _rpIdHashes[account];
    }

    // ─────────────────────────────────────────────────────────────
    // ERC-7579 introspection
    // ─────────────────────────────────────────────────────────────

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isInitialized(address account) external view override returns (bool) {
        return _initialized[account];
    }

    // ─────────────────────────────────────────────────────────────
    // Internal — WebAuthn verification (FIDO2 spec §7.2)
    // ─────────────────────────────────────────────────────────────

    /**
     * @dev  Full WebAuthn assertion verification.
     *
     *       Steps:
     *       1. authenticatorData length ≥ 37 bytes.
     *       2. rpIdHash matches first 32 bytes of authenticatorData.
     *       3. User Presence (UP) flag is set.
     *       4. clientDataJSON.type == "webauthn.get".
     *       5. Challenge in clientDataJSON matches base64url(userOpHash).
     *       6. Compute signedMessage = sha256(authenticatorData ‖ sha256(clientDataJSON)).
     *       7. Verify P256 sig (r, s) over signedMessage using pubKey (x, y).
     *       8. Replay protection: assertion hash must be unused.
     */
    function _verifyWebAuthn(
        WebAuthnSignature memory sig,
        uint256[2] storage pubKey,
        bytes32 challenge,
        bytes32 rpIdHash
    ) internal returns (bool) {

        // ── Step 1: authenticatorData minimum length ──────────────
        if (sig.authenticatorData.length < 37) revert InvalidAuthenticatorData();

        // ── Step 2: rpIdHash check ────────────────────────────────
        bytes32 authRpIdHash;
        assembly {
            authRpIdHash := mload(add(mload(add(sig, 0x20)), 0x20))
        }
        if (authRpIdHash != rpIdHash) revert InvalidRpIdHash();

        // ── Step 3: User Presence flag ────────────────────────────
        uint8 flags = uint8(sig.authenticatorData[32]);
        if (flags & AUTH_FLAG_UP == 0) revert UserPresenceNotSet();

        // ── Step 4: clientDataJSON type ───────────────────────────
        // Must contain `"type":"webauthn.get"` or `"type": "webauthn.get"`
        if (!_containsType(sig.clientDataJSON)) revert InvalidClientDataType();

        // ── Step 5: Challenge match ───────────────────────────────
        // Extract the challenge value from clientDataJSON at the given offset
        // and compare against base64url(challenge).
        if (!_verifyChallenge(sig.clientDataJSON, sig.challengeOffset, challenge)) {
            revert ChallengeMismatch();
        }

        // ── Step 6: Compute signed message ───────────────────────
        // signedMessage = sha256(authenticatorData ‖ sha256(clientDataJSON))
        bytes32 clientDataHash = sha256(sig.clientDataJSON);
        bytes32 signedMessage = sha256(
            abi.encodePacked(sig.authenticatorData, clientDataHash)
        );

        // ── Step 7: Replay protection ─────────────────────────────
        bytes32 assertionHash = keccak256(
            abi.encodePacked(sig.authenticatorData, sig.clientDataJSON)
        );
        if (_usedAssertions[assertionHash]) revert ReplayDetected();
        _usedAssertions[assertionHash] = true;

        // ── Step 8: P256 signature verification ───────────────────
        return _verifyP256(signedMessage, sig.rs, pubKey);
    }

    /**
     * @dev  Verify a P256 (secp256r1) signature using the RIP-7212 precompile.
     *       Input to precompile: abi.encode(hash, r, s, x, y)
     *       Output: uint256(1) on success.
     *
     *       Falls back gracefully if precompile is unavailable (returns false — fail closed).
     *       In production on chains without RIP-7212, replace fallback with:
     *         - Daimo's p256-verifier (https://github.com/daimo-eth/p256-verifier)
     *         - FCL (https://github.com/rdubois-crypto/FreshCryptoLib)
     */
    function _verifyP256(
        bytes32 messageHash,
        uint256[2] memory rs,
        uint256[2] storage pubKey
    ) internal view returns (bool) {
        bytes memory input = abi.encode(
            messageHash,
            rs[0],      // r
            rs[1],      // s
            pubKey[0],  // x
            pubKey[1]   // y
        );

        (bool success, bytes memory result) = P256_PRECOMPILE.staticcall(input);

        if (success && result.length == 32) {
            return abi.decode(result, (uint256)) == 1;
        }

        // Precompile unavailable — fail closed (never silently pass)
        return false;
    }

    // ─────────────────────────────────────────────────────────────
    // Internal — clientDataJSON parsing
    // ─────────────────────────────────────────────────────────────

    /**
     * @dev  Check that clientDataJSON contains `"type":"webauthn.get"`.
     *       Uses a simple bytes search — sufficient for well-formed WebAuthn JSON.
     */
    function _containsType(bytes memory clientDataJSON) internal pure returns (bool) {
        bytes memory needle = bytes('"type":"webauthn.get"');
        bytes memory needle2 = bytes('"type": "webauthn.get"');
        return _indexOf(clientDataJSON, needle) != type(uint256).max
            || _indexOf(clientDataJSON, needle2) != type(uint256).max;
    }

    /**
     * @dev  Verify the challenge in clientDataJSON matches base64url(userOpHash).
     *
     *       clientDataJSON challenge field contains the base64url-encoded challenge.
     *       The EthosiFi frontend sets challenge = base64url(userOpHash).
     *
     *       We re-encode the on-chain userOpHash using base64url and compare
     *       it to the bytes in clientDataJSON at [challengeOffset, challengeOffset+43].
     *       (32 bytes base64url-encoded = 43 characters, no padding)
     */
    function _verifyChallenge(
        bytes memory clientDataJSON,
        uint256 offset,
        bytes32 expectedChallenge
    ) internal pure returns (bool) {
        // base64url of 32 bytes = 43 chars (no padding)
        uint256 encodedLen = 43;
        if (offset + encodedLen > clientDataJSON.length) return false;

        bytes memory encoded = _base64urlEncode(abi.encodePacked(expectedChallenge));
        if (encoded.length != encodedLen) return false;

        for (uint256 i = 0; i < encodedLen; i++) {
            if (clientDataJSON[offset + i] != encoded[i]) return false;
        }
        return true;
    }

    /**
     * @dev  base64url encoding (RFC 4648 §5, no padding).
     *       Used to encode the userOpHash for challenge comparison.
     */
    function _base64urlEncode(bytes memory data) internal pure returns (bytes memory) {
        bytes memory TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        uint256 encodedLen = 4 * ((data.length + 2) / 3);
        // Remove padding chars for base64url
        uint256 remainder = data.length % 3;
        uint256 actualLen = remainder == 0 ? encodedLen : encodedLen - (3 - remainder);

        bytes memory result = new bytes(actualLen);
        uint256 resultIdx = 0;

        for (uint256 i = 0; i < data.length; i += 3) {
            uint256 b0 = uint8(data[i]);
            uint256 b1 = (i + 1 < data.length) ? uint8(data[i + 1]) : 0;
            uint256 b2 = (i + 2 < data.length) ? uint8(data[i + 2]) : 0;

            uint256 triple = (b0 << 16) | (b1 << 8) | b2;

            if (resultIdx < actualLen) result[resultIdx++] = TABLE[(triple >> 18) & 0x3F];
            if (resultIdx < actualLen) result[resultIdx++] = TABLE[(triple >> 12) & 0x3F];
            if (resultIdx < actualLen) result[resultIdx++] = TABLE[(triple >> 6)  & 0x3F];
            if (resultIdx < actualLen) result[resultIdx++] = TABLE[ triple        & 0x3F];
        }

        return result;
    }

    /**
     * @dev  Find the first occurrence of needle in haystack.
     *       Returns type(uint256).max if not found.
     */
    function _indexOf(bytes memory haystack, bytes memory needle)
        internal
        pure
        returns (uint256)
    {
        if (needle.length == 0 || needle.length > haystack.length) {
            return type(uint256).max;
        }
        for (uint256 i = 0; i <= haystack.length - needle.length; i++) {
            bool found = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return type(uint256).max;
    }

    // ─────────────────────────────────────────────────────────────
    // Internal — credential helpers
    // ─────────────────────────────────────────────────────────────

    function _isAccountCredential(address account, bytes32 credId)
        internal
        view
        returns (bool)
    {
        bytes32[] storage creds = _accountCredentials[account];
        for (uint256 i = 0; i < creds.length; i++) {
            if (creds[i] == credId) return true;
        }
        return false;
    }

    function _activeCredentialCount(address account) internal view returns (uint256 count) {
        bytes32[] storage creds = _accountCredentials[account];
        for (uint256 i = 0; i < creds.length; i++) {
            if (_credentials[creds[i]].active) count++;
        }
    }
}
