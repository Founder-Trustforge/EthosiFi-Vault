// Compiles the project + the real EntryPoint / MSAAdvanced + test helpers with solc-js (Cancun, viaIR)
// and writes artifacts.json for the hardhat integration suite. Takes ~1-2 minutes.
const solc = require('solc'), fs = require('fs'), path = require('path');
const I = __dirname, P = path.resolve(I, '..');
function read(unit) {
  for (const [pre, base] of [['node_modules/', I], ['deps/', I], ['contracts/', I]]) {
    if (unit.startsWith(pre)) { try { return fs.readFileSync(path.join(base, unit), 'utf8'); } catch (e) { return null; } }
  }
  try { return fs.readFileSync(path.join(P, unit), 'utf8'); } catch (e) { return null; }
}
const sources = {};
const add = (unit) => { const c = read(unit); if (c === null) throw new Error('missing ' + unit + ' (run `bash setup.sh` first?)'); sources[unit] = { content: c }; };
for (const f of fs.readdirSync(P + '/src')) if (f.endsWith('.sol')) add('src/' + f);
const L = 'lib/erc7579-implementation/src/';
['MSAAdvanced.sol', 'utils/MSAProxy.sol', 'utils/Bootstrap.sol'].forEach((f) => add(L + f));
add('lib/account-abstraction/contracts/core/EntryPoint.sol');
add('deps/p256-verifier/src/P256Verifier.sol');
for (const f of fs.readdirSync(I + '/contracts')) if (f.endsWith('.sol')) add('contracts/' + f);
const input = { language: 'Solidity', sources, settings: {
  evmVersion: 'cancun', viaIR: true, optimizer: { enabled: true, runs: 200 },
  remappings: [
    'erc7579/=lib/erc7579-implementation/src/', 'account-abstraction/=lib/account-abstraction/contracts/',
    'solady/=lib/solady/src/', 'forge-std/=lib/forge-std/src/', 'sentinellist/=deps/sentinellist/src/',
    '@openzeppelin/=node_modules/@openzeppelin/',
    'lib/erc7579-implementation/:src/=lib/erc7579-implementation/src/'],
  outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object'] } } } };
const out = JSON.parse(solc.compile(JSON.stringify(input), { import: (u) => { const c = read(u); return c === null ? { error: 'not found ' + u } : { contents: c }; } }));
let bad = 0; for (const e of out.errors || []) if (e.severity === 'error') { bad++; console.log(e.formattedMessage); }
if (bad) { console.log('BUILD FAILED'); process.exit(1); }
const res = {};
for (const [f, cs] of Object.entries(out.contracts)) for (const [n, c] of Object.entries(cs)) {
  if (!c.evm.bytecode.object) continue;
  const key = res[n] ? path.basename(f, '.sol') + ':' + n : n;
  res[key] = { abi: c.abi, bin: '0x' + c.evm.bytecode.object, deployedBin: '0x' + c.evm.deployedBytecode.object, file: f };
}
fs.writeFileSync(I + '/artifacts.json', JSON.stringify(res));
const big = Object.entries(res).filter(([n, a]) => (a.deployedBin.length - 2) / 2 > 24576).map(([n]) => n);
console.log('BUILD OK', Object.keys(res).length, 'contracts; over 24576B:', big.join(',') || 'none');
