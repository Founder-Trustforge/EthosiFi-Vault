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

The vault is a standard ERC-4337 v0.7 / ERC-7579 smart account (rhinestone `MSAAdvanced` behind an
`MSAProxy`), created and fully configured **atomically** by `VaultFactory` (no half-configured window).

```
                    ┌────────────── who may sign (validators) ──────────────┐
 fingerprint   ───▶ │ BiometricValidator   passkey (WebAuthn P-256, UV)  FULL │
 spending key  ───▶ │ TimeLockValidator    own key: small transfers only      │
 guardians     ───▶ │ GuardianValidator    time-delayed passkey recovery only │
                    └──────────────────────────┬─────────────────────────────┘
                                               ▼
                          MSAAdvanced.execute / executeFromExecutor / (un)installModule
                                               │  single hook slot
                                               ▼
                    ┌──────────── EthosiHookRouter (every call, every inner call) ────────────┐
                    │ TimeLockValidator  spending-key velocity budget (24h, ≤10 txs, per token) │
                    │ EmergencyFreeze    guardian panic button                                  │
                    │ MultiSigUpgradeGuard  module changes need guardian consensus + delay      │
                    │ AntiScamScreener   flagged recipients / spenders (transfer, approve, …)   │
                    │ PoisonedAddressProtection  address-poisoning + full-address confirmation  │
                    │ SeniorModeGuard    hours, approved recipients, per-token daily limits     │
                    └───────────────────────────────────────────────────────────────────────────┘
```

* **Two-tier authority.** Only the passkey (fingerprint, `userVerification` required) has full authority.
  The *spending key* is a separate key that can do exactly three things: send native / ERC-20 `transfer`
  up to a per-tx cap, queue a delayed transaction, cancel one. It cannot approve, batch, delegatecall,
  install modules, change policy, rotate itself or sign messages.
* **No drip-drain.** Every spending-key transfer is charged against an exact sliding-window budget per
  token (24h, at most 10 transfers, at most `windowLimit`). Over budget → the execution reverts.
  Tokens without a policy are untouchable by the spending key; enabling one is queued for 48h.
* **Fingerprint-confirmed release, 48h expiry.** Anything larger (or over budget) is queued with
  `initiateDelayedTx`. The off-chain notifier texts the owner a link; the funds move only when a WebAuthn
  fingerprint assertion over `confirmationChallenge(account, txHash)` reaches `confirmAndRelease`. The SMS
  is only a notification — a SIM-swapper cannot release anything. Unconfirmed after 48h → dead.
* **Gas tank.** A spending-key op must be prefunded entirely from the vault's EntryPoint deposit, never from
  its balance, so a stolen spending key can burn at most the tank (`createVault{value}` funds it).
* **Router fail-closed.** `execute` single/batch inner calls are decoded exactly as the account decodes them;
  malformed encodings revert; delegatecall/unknown call types are refused while the router is installed.
  Policy hooks only accept calls from the router (`RouterGated`).

### What is NOT protected (read this)

* A stolen **passkey + the owner's fingerprint** has full authority (as with any signing key). Hooks still
  apply (freeze, scam screening, senior limits) but the budget/delay tier does not.
* Passkey signatures are blind (WebAuthn signs a hash): the wallet UI is responsible for showing what is signed.
* The threat registries (`AntiScamScreener`, `PoisonedAddressProtection`) are owned by EthosiFi: that owner can
  *block* destinations, never move funds. Put the owner behind a multisig.
* Validation uses `block.timestamp`-free logic but touches EntryPoint deposit/transient storage; run your own
  bundler (or stake the entities) before relying on public ERC-7562 mempools.
* `PlainEnglishExecutor`, `AIThreatOracle`, `DeepfakeGuard` are **experimental and not allow-listed** by the
  factory; `experimental/PaymasterManager.sol` (moved out of `src/`) is not a real ERC-4337 paymaster yet. Do not rely on them.
* Requires the EIP-7951/RIP-7212 P-256 precompile at `0x100` (Sepolia: yes since Fusaka; fail-closed otherwise).
* Not externally audited. Do not use with real funds.

**Transaction flow**
```
UserOp ─▶ EntryPoint ─▶ account.validateUserOp ─▶ validator chosen by the nonce key
       ─▶ account.execute ─▶ EthosiHookRouter ─▶ [budget, freeze, upgrade guard, screener, …] ─▶ call
```

---

## Contract Reference

### Authorities

| Contract | Description |
|----------|-------------|
| `BiometricValidator.sol` | WebAuthn/FIDO2 passkey = fingerprint. Per-account credentials, UV flag + rpId (`ethosifi.com`) enforced, challenge bound to the userOpHash. |
| `TimeLockValidator.sol` | Spending key validator + velocity budget (sub-hook) + delayed tx queue + fingerprint release + per-token policy (loosening queued). |
| `GuardianValidator.sol` | Weighted social recovery (executor): replaces the passkey after threshold weight + 48h; any guardian/the user can cancel. |

### Policy hooks (behind `EthosiHookRouter`)

| Contract | Description |
|----------|-------------|
| `EmergencyFreeze.sol` | Any guardian freezes ALL outgoing calls in one block; guardian vote to unfreeze. |
| `MultiSigUpgradeGuard.sol` | `installModule` / `uninstallModule` only with guardian consensus + delay (single-use grant). |
| `AntiScamScreener.sol` | Blocks flagged targets AND flagged recipients/spenders inside transfer/approve/transferFrom/setApprovalForAll. |
| `PoisonedAddressProtection.sol` | Lookalike-address refusal + single-use full-address confirmation for large first-time transfers. |
| `SeniorModeGuard.sol` | Allowed hours, guardian-approved recipients, per-token tx/daily limits (increases queued 24h). |

### Infrastructure

| Contract | Description |
|----------|-------------|
| `VaultFactory.sol` | Deploys `MSAProxy` + `EthosiBootstrap` in the proxy constructor. Immutable addresses, no owner, CREATE2 (`getAddress`). `msg.value` funds the gas tank. |
| `EthosiHookRouter.sol` | The account's single hook; fans every call out to per-account sub-hooks. |
| `EthosiBootstrap.sol` | Delegatecalled once at init to install validators, executors and the router. |
| `Deploy.s.sol` | Forge script: deploys everything in dependency order. |

### Experimental (not allow-listed)

`PlainEnglishExecutor`, `AIThreatOracle`, `DeepfakeGuard` (in `src/`) and `experimental/PaymasterManager.sol` — see limitations above.

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
| SeniorModeGuard | `pending` |
| EthosiHookRouter | `pending` |
| EthosiBootstrap | `pending` |

---

## Testing

```bash
# Integration suite: real EntryPoint v0.7 + real MSAAdvanced account + all modules, on a Cancun EVM
cd integration-tests && npm install && npm run build && npm test
```

Three suites run with `npm test`:

* `suite.js` (40 tests) deploys the factory and creates vaults through it, then drives real ERC-4337 `handleOps`
  flows: passkey and spending-key sends, budget/drip-drain limits, delayed tx + fingerprint release + 48h expiry,
  guardian recovery, every policy hook, a calldata-mutation fuzz of the router, reentrancy and attacker scenarios.
* `suite_token.js` (19 tests): `$ETHOS` token, badge, staking, governance and the LP manager with a mock Uniswap V3
  pool, including a check of the tick/liquidity math against a high-precision reference.
* `suite_offchain.js` (8 tests): the phone-enrollment service logic against the real `BiometricValidator`
  with a real passkey assertion.

`forge test` only covers the pure V3 math (`test/`); the end-to-end suites above are the real coverage.
CI runs both. Nothing here replaces an external audit.

## Token suite notes

* `$ETHOS` burns from someone else's balance now need that holder's allowance (subscription burns require the
  provider to `approve` the burner for at least the fee). `distributePool` lets the owner release the 50M tokens
  the contract holds (rewards pool + unvested team half); the owner SHOULD be a multisig.
* Badge is a single soulbound token with per-source tiers (staking = MVP, LP = Gold). Losing one source keeps the other.
  Badge calls never block staking or unstaking, even if the badge contract is replaced or broken.
* Governance votes only count stake that existed before the proposal (`votingPowerSince`), voting closes strictly at
  `endTime`, and a passed proposal must be executed within 14 days of its timelock. The owner can still cancel active
  proposals and edit the target/selector whitelist: that is a deliberate trust anchor until governance owns itself.
* LP positions are valued with real Uniswap V3 math at the pool's 30-minute TWAP (never spot), one provider per
  position NFT, only the configured fee tier. A position that moves, empties, or misses its monthly burn past a 7-day
  grace can be deactivated by anyone. The pool needs >= 30 min of observation history; registration fails closed before.
* Deploy with `forge script script/DeployToken.s.sol` (wires everything), then transfer every `owner` to a multisig.

---

## Security & Audits

### Audit Status

| Firm | Status | Report |
|------|--------|--------|
| TBD | Not yet engaged | — |

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
| **Vault** | [ethosifi.com](https://ethosifi.com) |
| **Community Hub** | [ethosifi.xyz](https://ethosifi.xyz) |
| **Twitter/X** | [@ethosifi](https://twitter.com/ethosifi) |
| **GitHub** | [github.com/Founder-Trustforge/EthosiFi-Vault](https://github.com/Founder-Trustforge/EthosiFi-Vault) |

---

*© 2025 EthosiFi, Inc. Built with ❤️ for the people who've lost enough.*
