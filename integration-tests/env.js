// Integration test environment: hardhat EDR (Cancun) + real EntryPoint v0.7 at its canonical address + P-256 verifier at 0x100
const hre = require('hardhat');
const { ethers } = require('ethers');
const fs = require('fs');
const A = JSON.parse(fs.readFileSync(__dirname + '/artifacts.json', 'utf8')); // produced by build.js
const EP_ADDR = '0x0000000071727De22E5E9d8BAf0edAc6f37da032';

async function setup() {
  const provider = new ethers.BrowserProvider(hre.network.provider, undefined, { cacheTimeout: -1 });
  const signers = [];
  for (let i = 0; i < 12; i++) signers.push(await provider.getSigner(i));
  const deployer = signers[0];
  const deploy = async (name, args = [], signer = deployer) => {
    const a = A[name]; if (!a) throw new Error('no artifact ' + name);
    const f = new ethers.ContractFactory(a.abi, a.bin, signer);
    const c = await f.deploy(...args); await c.waitForDeployment(); return c;
  };
  const at = (name, addr, signer = deployer) => new ethers.Contract(addr, A[name].abi, signer);
  // EntryPoint: deploy normally (it creates its SenderCreator), then clone its runtime code to the canonical address
  const ep0 = await deploy('EntryPoint');
  const code = await provider.getCode(await ep0.getAddress());
  await hre.network.provider.send('hardhat_setCode', [EP_ADDR, code]);
  // SenderCreator pins its EntryPoint as an immutable: re-point it from the throwaway EP to the canonical address
  const sc = await ep0.senderCreator();
  const scCode = await provider.getCode(sc);
  const from = (await ep0.getAddress()).slice(2).toLowerCase(), to = EP_ADDR.slice(2).toLowerCase();
  if (!scCode.toLowerCase().includes(from)) throw new Error('SenderCreator immutable not found');
  await hre.network.provider.send('hardhat_setCode', [sc, scCode.toLowerCase().split(from).join(to)]);
  const entryPoint = at('EntryPoint', EP_ADDR);
  // P-256 verifier at the RIP-7212 / EIP-7951 precompile address
  await hre.network.provider.send('hardhat_setCode', ['0x0000000000000000000000000000000000000100', A['P256Verifier'].deployedBin]);
  const send = (m, p = []) => hre.network.provider.send(m, p);
  const increaseTime = async (s) => { await send('evm_increaseTime', [s]); await send('evm_mine'); };
  const now = async () => (await provider.getBlock('latest')).timestamp;
  return { hre, provider, signers, deployer, deploy, at, entryPoint, EP_ADDR, A, send, increaseTime, now, ethers };
}
module.exports = { setup, EP_ADDR };
