#!/usr/bin/env bash
# Fetches the two third-party test dependencies that are not git submodules of the main repo.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p deps
[ -d deps/p256-verifier ] || git clone --depth 1 https://github.com/daimo-eth/p256-verifier deps/p256-verifier
[ -d deps/sentinellist ]  || git clone --depth 1 https://github.com/rhinestonewtf/sentinellist deps/sentinellist
# the reference verifier pins an exact compiler; relax it so it builds with the project compiler
sed -i 's/pragma solidity 0\.8\.[0-9]*;/pragma solidity ^0.8.21;/' deps/p256-verifier/src/P256Verifier.sol
npm install --no-audit --no-fund
echo "now: npm run build && npm test"
