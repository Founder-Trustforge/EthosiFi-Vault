# EthosiFi Vault

### The Unstealable Wallet.

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](./LICENSE)
[![Built on ERC-7579](https://img.shields.io/badge/Standard-ERC--7579-green.svg)](https://eips.ethereum.org/EIPS/eip-7579)
[![ERC-4337](https://img.shields.io/badge/Standard-ERC--4337-green.svg)](https://eips.ethereum.org/EIPS/eip-4337)
[![Testnet: Sepolia](https://img.shields.io/badge/Testnet-Sepolia-orange.svg)](https://ethosifi.xyz)
[![Audit: Pending](https://img.shields.io/badge/Audit-Pending-yellow.svg)](#security)

> **$3.5 billion in crypto was stolen in 2025. Not because the technology failed — because every wallet put a warning label on a loaded gun and called it security. EthosiFi Vault does something different: it makes theft structurally impossible at the blockchain level.**

---

## Table of Contents

- [What is EthosiFi Vault?](#what-is-ethosifi-vault)
- [The Problem We Solve](#the-problem-we-solve)
- [Architecture](#architecture)
- [Contract Reference](#contract-reference)
- [Security Model](#security-model)
- [Quick Start](#quick-start)
- [Deployment](#deployment)
- [Testing](#testing)
- [Security & Audits](#security--audits)
- [Pricing](#pricing)
- [License](#license)
- [Contact](#contact)

---

## What is EthosiFi Vault?

EthosiFi Vault is a **smart contract wallet** built on [ERC-7579](https://eips.ethereum.org/EIPS/eip-7579) and [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) that enforces security at the **smart contract layer** — not just the user interface.

Every competitor warns users about threats. EthosiFi Vault **prevents them at the blockchain level**, making it physically impossible for attackers to bypass protection — even if your phone, keys, guardians, or signing device are compromised.

**No seed phrases. No gas fees. No single point of failure.**

---

## The Problem We Solve

| Threat | Industry Response | EthosiFi Response |
|--------|------------------|-------------------|
| Stolen private keys | "Keep your seed phrase safe" | Time-lock + biometric bypass — keys alone can't drain funds |
| Address poisoning | UI warning (if any) | On-chain full-address enforcement + lookalike detection |
| Blind signing | "Check before you sign" | Plain English transaction translation — committed on-chain |
| Phishing / scams | UI alert | Real-time threat screening — blocks at contract level |
| AI deepfake attacks | None | Timed human verification challenge |
| Social engineering | None | Behavioral pressure detection + mandatory cooloff |
| Malicious upgrades | None | Guardian multi-sig + 72h delay on all module changes |
| Elder exploitation | None | Senior Mode — full guardian control and daily limits |

---

## Architecture

```
User Request
     │
     ▼
┌─────────────────────────────────────────────────────┐
│                   VaultFactory                       │
│         (One-click deployment, CREATE2)              │
└─────────────────────┬───────────────────────────────┘
                      │ Installs all modules
                      ▼
┌─────────────────────────────────────────────────────┐
│              EthosiFi Smart Account                  │
│                  (ERC-7579)                          │
│                                                      │
│  ┌──────────────────────────────────────────────┐   │
│  │           LAYER 1: CORE SECURITY             │   │
│  │  BiometricValidator  →  TimeLockValidator    │   │
│  │  GuardianValidator   →  EmergencyFreeze      │   │
│  │  MultiSigUpgradeGuard                        │   │
│  └──────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────┐   │
│  │         LAYER 2: USER PROTECTION             │   │
│  │  PoisonedAddressProtection → AntiScamScreener│   │
│  │  PlainEnglishExecutor → AIThreatOracle       │   │
│  │  DeepfakeGuard                               │   │
│  └──────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────┐   │
│  │          LAYER 3: UX & ACCESSIBILITY         │   │
│  │  SeniorModeValidator  →  PaymasterManager    │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
                      │
                      ▼
              ERC-4337 EntryPoint
                      │
                      ▼
                  Execution
```

**Transaction Flow:**
```
UserOp → BiometricValidator (auth) → AIThreatOracle (risk score)
       → AntiScamScreener (threat check) → PoisonedAddressProtection (address verify)
       → PlainEnglishExecutor (human confirm) → TimeLockValidator (delay if needed)
       → DeepfakeGuard (challenge if large) → PaymasterManager (gasless)
       → Execution
```

---

## Contract Reference

### Layer 1 — Core Security

| Contract | Description |
|----------|-------------|
| `TimeLockValidator.sol` | **The heart of the vault.** Mandatory 48-hour delay on high-value transfers (>$10k). Biometric bypass for instant execution. Guardians can cancel or approve during the window. |
| `BiometricValidator.sol` | WebAuthn/FIDO2 biometric verification. Binds Face ID / Touch ID directly to signing authority. No seed phrases. Uses P256 curve (EIP-7212 compatible). |
| `GuardianValidator.sol` | Weighted social recovery network. Threshold-based consensus with cooldown periods. The human firewall that backs up the technical one. |
| `EmergencyFreeze.sol` | Instant panic button. Any guardian freezes ALL outgoing transactions in one block. Guardian multi-sig required to unfreeze. |
| `MultiSigUpgradeGuard.sol` | Prevents ANY module upgrade without guardian consensus + 72-hour delay. Closes the supply-chain attack vector behind the Bybit and Trust Wallet breaches. |

### Layer 2 — User Protection

| Contract | Description |
|----------|-------------|
| `PoisonedAddressProtection.sol` | Forces full address display and on-chain confirmation before transfers. Detects lookalike addresses (first/last byte matching). Kills address poisoning — 65.4M attacks detected in 2025. |
| `AntiScamScreener.sol` | Real-time screening against malicious contracts, phishing addresses, and rug-pull tokens. Blocks BEFORE the mempool. Integrates with Chainalysis and Cyvers threat feeds. |
| `PlainEnglishExecutor.sol` | Translates every transaction into human language before signing. Kills blind signing — root cause of 90% of DeFi exploits. On-chain committed summaries. |
| `AIThreatOracle.sol` | Real-time AI risk scoring (0–100) per transaction. Factors: recipient history, contract age, behavioral anomalies, attack patterns. Scores above 85 are auto-blocked. |
| `DeepfakeGuard.sol` | Timed cryptographic challenge for large transfers. Defends against AI voice/video impersonation (up 1,633% in Q1 2025). Detects social engineering pressure via rapid-attempt tracking. |

### Layer 3 — UX & Accessibility

| Contract | Description |
|----------|-------------|
| `SeniorModeValidator.sol` | Maximum protection for elderly users. Daily limits, time-of-day restrictions, guardian control of all address approvals, mandatory delays on ALL transfers. |
| `PaymasterManager.sol` | Full ERC-4337 gasless infrastructure. Pay fees in USDC, DAI, or USDT. Never hold ETH. 10 free sponsored tx/month on Free tier. |

### Infrastructure

| Contract | Description |
|----------|-------------|
| `VaultFactory.sol` | One-click vault deployment with all 12 modules pre-installed. CREATE2 deterministic addresses — know your vault address before deployment. |
| `Deploy.s.sol` | Forge deployment script. Sequential deployment with address linking, env var management, and full Etherscan verification support. |

---

## Security Model

### The Layered Defense

EthosiFi uses a **defense-in-depth** approach. An attacker must defeat ALL of the following simultaneously:

1. **Biometric auth** — requires your physical biology
2. **AI risk scoring** — flags anomalous transactions before execution
3. **Anti-scam screening** — blocks known malicious addresses
4. **Address verification** — prevents lookalike address substitution
5. **Plain English confirmation** — eliminates blind signing
6. **Time-lock delay** — 48-hour window for detection
7. **Guardian network** — trusted humans can freeze or cancel
8. **Emergency freeze** — instant halt on suspicious activity
9. **Deepfake challenge** — verifies human presence for large transfers
10. **Upgrade guard** — prevents silent contract replacement

**Breaking one layer is not enough. Breaking all ten simultaneously is structurally impossible.**

### What EthosiFi Cannot Protect Against

In the spirit of full transparency, no system is perfect. EthosiFi cannot protect against:

- A user who manually disables all security modules
- A user who is physically coerced into approving transactions
- Smart contract bugs (mitigated by external audits — see [Security & Audits](#security--audits))
- Bugs in the underlying ERC-7579/ERC-4337 infrastructure

We publish all known limitations. If you find one we haven't listed, please report it via our [responsible disclosure policy](./SECURITY.md).

---

## Quick Start

### Prerequisites

- [Foundry](https://getfoundry.sh/) installed
- Node.js 18+
- A Sepolia RPC URL (Alchemy or Infura)

### Installation

```bash
git clone https://github.com/Founder-Trustforge/EthosiFi-Vault.git
cd EthosiFi-Vault
forge install
npm install
```

### Environment Setup

```bash
cp .env.example .env
# Fill in:
# PRIVATE_KEY=your_deployer_private_key
# SEPOLIA_RPC=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
# ETHERSCAN_API_KEY=your_etherscan_key
# ENTRY_POINT=0x0000000071727De22E5E9d8BAf0edAc6f37da032
```

### Compile

```bash
forge build
```

---

## Deployment

### Sepolia Testnet

```bash
forge script script/Deploy.s.sol \
  --rpc-url $SEPOLIA_RPC \
  --broadcast \
  --verify \
  -vvv
```

### Verify Contracts

```bash
forge verify-contract <ADDRESS> TimeLockValidator \
  --chain-id 11155111 \
  --etherscan-api-key $ETHERSCAN_API_KEY
```

### Deployed Addresses (Sepolia)

> Coming soon — testnet deployment in progress.

| Contract | Address |
|----------|---------|
| VaultFactory | `pending` |
| TimeLockValidator | `pending` |
| BiometricValidator | `pending` |
| GuardianValidator | `pending` |
| EmergencyFreeze | `pending` |
| MultiSigUpgradeGuard | `pending` |
| PoisonedAddressProtection | `pending` |
| AntiScamScreener | `pending` |
| PlainEnglishExecutor | `pending` |
| AIThreatOracle | `pending` |
| DeepfakeGuard | `pending` |
| SeniorModeValidator | `pending` |
| PaymasterManager | `pending` |

---

## Testing

```bash
# Run all tests
forge test -vv

# Run with gas report
forge test --gas-report

# Fuzz testing
forge test --fuzz-runs 10000

# Static analysis
slither src/
```

### Test Coverage Targets

| Module | Unit Tests | Integration | Fuzz |
|--------|-----------|-------------|------|
| TimeLockValidator | ✅ | ✅ | ✅ |
| BiometricValidator | ✅ | ✅ | — |
| GuardianValidator | ✅ | ✅ | ✅ |
| EmergencyFreeze | ✅ | ✅ | — |
| PoisonedAddressProtection | ✅ | ✅ | ✅ |
| All others | In progress | In progress | In progress |

---

## Security & Audits

### Audit Status

| Firm | Status | Report |
|------|--------|--------|
| TBD | Scheduled Q2 2026 | Pending |

We will publish the **complete, unredacted audit report** upon completion.  
No production mainnet deployment will occur before a full external audit.

### Bug Bounty

Live on [Immunefi](https://immunefi.com) — details coming soon.

| Severity | Reward |
|----------|--------|
| Critical | Up to $50,000 |
| High | Up to $10,000 |
| Medium | Up to $2,500 |
| Low | Up to $500 |

### Responsible Disclosure

See [SECURITY.md](./SECURITY.md) for our responsible disclosure policy.  
Email: security@ethosifi.com

---

## Pricing

| Tier | Price | Features |
|------|-------|----------|
| Free | $0/mo | Up to $1,000 volume, 10 tx/mo, 48h time-lock, 1 guardian |
| Pro | $9.99/mo | Unlimited volume, biometric bypass, 3 guardians, AI fraud monitoring |
| Family | $19.99/mo | Everything in Pro, 5 sub-accounts, shared guardians |
| Enterprise | Custom | White-label SDK, custom integration, institutional support |

---

## License

EthosiFi Vault is licensed under the **Business Source License 1.1 (BSL 1.1)**.

- **Non-commercial use**: Free (personal, educational, research)
- **Commercial use**: Contact founder@ethosifi.com for licensing
- **Open source conversion**: Converts to GPL-3.0 on January 1, 2029

See [LICENSE](./LICENSE) for full terms.

---

## Contact

| | |
|--|--|
| **Founder** | founder@ethosifi.com |
| **Security** | security@ethosifi.com |
| **Enterprise** | enterprise@ethosifi.com |
| **Website** | [ethosifi.xyz](https://ethosifi.xyz) |
| **Twitter/X** | [@ethosifi](https://twitter.com/ethosifi) |
| **GitHub** | [github.com/Founder-Trustforge/EthosiFi-Vault](https://github.com/Founder-Trustforge/EthosiFi-Vault) |

---

*© 2025 EthosiFi, Inc. Built with ❤️ for the people who've lost enough.*
