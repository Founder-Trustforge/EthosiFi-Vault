# Integration tests

Real ERC-4337 v0.7 `EntryPoint` + real rhinestone `MSAAdvanced` account + every EthosiFi module, executed on
Hardhat's EDR (Cancun). Vaults are created through `VaultFactory` and driven with `EntryPoint.handleOps`
(the Daimo P-256 verifier is etched at `0x100` to stand in for the EIP-7951 precompile).

    bash setup.sh        # clones deps, npm install
    npm run build        # solc-js, viaIR, ~1-2 min  -> artifacts.json
    npm test             # ~1 min

Covers: factory + wiring, passkey sends, spending-key limits (value, count, bundles, gas tank, confinement),
delayed tx + fingerprint release + 48h expiry + reentrancy, freeze, anti-scam, multisig upgrade guard,
poisoned-address hook, senior mode, guardian recovery, router calldata-mutation fuzz, attacker scenarios.
Foundry unit/fuzz tests are still to be written.
