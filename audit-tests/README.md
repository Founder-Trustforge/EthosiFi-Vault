Behavior tests for TimeLockValidator on a local EVM (ganache) - used because Foundry was unavailable.
  npm i solc ganache ethers   (and sentinellist/forge-std not needed)
  node build.js && node test.js     # paths in build.js assume /tmp/vault-audit; adjust `root`
Port to Foundry (forge test) before relying on them; these do NOT exercise P256/WebAuthn (no RIP-7212 precompile locally).
