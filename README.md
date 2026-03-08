# Ethos-Wallet
The unstealable Wallet
## License

EthosiFi is licensed under the Business Source License 1.1 (BSL 1.1).

- **Non-commercial use**: Free (personal, educational, research)
- **Commercial use**: Contact founder@ethosifi.com for licensing
- **Open source**: Converts to GPL-3.0 on January 1, 2029

See [LICENSE](./LICENSE) for full terms.
# EthosiFi Vault

The unstealable wallet. Time-locked protection with biometric bypass.

## Overview

EthosiFi Vault is a smart contract wallet built on ERC-7579 that makes crypto assets unstealable through:

- **Time-locked withdrawals**: 48-hour mandatory delay on high-value transfers
- **Biometric bypass**: Face ID/Touch ID for instant transactions
- **Guardian network**: Social recovery with time delays
- **Gasless UX**: Pay in USDC, never hold ETH

## Architecture
UserOp → BiometricValidator → TimeLockValidator → GuardianValidator → Execution
(instant auth)       (delay if needed)   (recovery only)

## Contracts

- `TimeLockValidator.sol`: Core security with delays and bypass
- `BiometricValidator.sol`: WebAuthn/FIDO2 signature verification
- `GuardianValidator.sol`: Social recovery with time delays
