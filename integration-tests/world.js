const { setup } = require('./env');
const L = require('./lib');
const { ethers, abi, newPasskey, Kit } = L;

async function buildWorld() {
  const e = await setup();
  const W = { e };
  const d = e.deploy;
  W.router = await d('EthosiHookRouter');
  const R = await W.router.getAddress();
  W.bootstrap = await d('EthosiBootstrap');
  W.bio = await d('BiometricValidator');
  const B = await W.bio.getAddress();
  W.tl = await d('TimeLockValidator', [B, R, e.EP_ADDR]);
  W.guardian = await d('GuardianValidator', [B]);
  W.freeze = await d('EmergencyFreeze', [R]);
  W.multisig = await d('MultiSigUpgradeGuard', [R]);
  W.poison = await d('PoisonedAddressProtection', [R]);
  W.antiscam = await d('AntiScamScreener', [R]);
  W.senior = await d('SeniorModeGuard', [R]);
  W.plain = await d('PlainEnglishExecutor', [R]);
  W.impl = await d('MSAAdvanced');
  W.token = await d('MockToken');
  const addr = async (c) => c.getAddress();
  W.factory = await d('VaultFactory', [e.EP_ADDR, await addr(W.impl), await addr(W.bootstrap), R, B, await addr(W.tl), await addr(W.guardian),
    [await addr(W.freeze), await addr(W.multisig), await addr(W.poison), await addr(W.antiscam), await addr(W.senior)]]);
  W.kit = new Kit(e);
  // error decoding across all contracts
  e.errIfaces = Object.values(e.A).map((a) => new ethers.Interface(a.abi));
  W.s = e.signers; // 0 deployer,1 bundler,2 user-beneficiary, 3 attacker, 4..9 guardians/others
  W.names = { bob: e.signers[2], attacker: e.signers[3], g1: e.signers[4], g2: e.signers[5], g3: e.signers[6], rg1: e.signers[7], rg2: e.signers[8], rg3: e.signers[9], scammer: e.signers[10] };
  return W;
}

const ETH = ethers.parseEther;
// Build a VaultConfig. opts can override fields.
async function newVault(W, opts = {}) {
  const { e, names: N } = W;
  const passkey = opts.passkey || newPasskey('owner');
  const spender = opts.spender || ethers.Wallet.createRandom();
  const addr = (c) => c.getAddress();
  const subHooks = [];
  const want = opts.subs || ['freeze', 'multisig', 'poison', 'antiscam'];
  const dataFor = {
    freeze: abi.encode(['address[]', 'uint256', 'uint256'], [[N.g1.address, N.g2.address, N.g3.address], 2, 0]),
    multisig: abi.encode(['address[]', 'uint256'], [[N.g1.address, N.g2.address, N.g3.address], 2]),
    poison: abi.encode(['bool', 'uint256', 'uint256'], [false, ETH('1'), 0]),
    antiscam: abi.encode(['uint8', 'bool'], [3, false]),
    senior: opts.seniorData || '0x',
  };
  for (const k of want) subHooks.push({ module: await addr(W[k]), data: dataFor[k] });
  const tokenAddr = await addr(W.token);
  const cfg = {
    credentialId: passkey.credentialId,
    passkeyPubKey: [passkey.x, passkey.y],
    rpIdHash: ethers.sha256(ethers.toUtf8Bytes('ethosifi.com')),
    spendingSigner: opts.noSpender ? ethers.ZeroAddress : spender.address,
    cancelGuardians: [N.g1.address],
    delay: opts.delay ?? 0,
    policies: opts.policies ?? [
      { token: ethers.ZeroAddress, highValue: ETH('0.25'), windowLimit: ETH('1') },
      { token: tokenAddr, highValue: 300_000_000n, windowLimit: 1_000_000_000n },
    ],
    recoveryGuardians: [
      { addr: N.rg1.address, weight: 1n, identityHash: ethers.ZeroHash },
      { addr: N.rg2.address, weight: 1n, identityHash: ethers.ZeroHash },
      { addr: N.rg3.address, weight: 1n, identityHash: ethers.ZeroHash },
    ],
    recoveryThreshold: 2n,
    subHooks,
  };
  const salt = opts.salt || ethers.id('salt' + Math.random());
  const account = await W.factory.getAddress ? await W.factory['getAddress(bytes32,(bytes32,uint256[2],bytes32,address,address[],uint256,(address,uint128,uint128)[],(address,uint256,bytes32)[],uint256,(address,bytes)[]))'](salt, cfg) : null;
  if (!opts.counterfactual) {
    const tx = await W.factory.createVault(salt, cfg); await tx.wait();
  }
  if (opts.fund !== false) {
    await (await e.deployer.sendTransaction({ to: account, value: ETH('10') })).wait();
    await (await W.token.mint(account, 5_000_000_000n)).wait();
    if (opts.tank !== false) await (await e.entryPoint.depositTo(account, { value: ETH('0.5') })).wait();
  }
  return { account, passkey, spender, cfg, salt };
}
module.exports = { buildWorld, newVault, ETH };
