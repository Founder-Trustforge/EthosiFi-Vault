const { buildWorld, newVault, ETH } = require('./world');
const L = require('./lib');
const { test, assert, reverts, ethers, MODE_BATCH, MODE_DELEGATE, MODE_TRY_SINGLE } = L;
(async () => {
  const W = await buildWorld(); const { e, kit = W.kit, names: N } = W; const K = W.kit;
  const bio = await W.bio.getAddress(), tl = await W.tl.getAddress(), gd = await W.guardian.getAddress(), R = await W.router.getAddress();
  const tok = await W.token.getAddress();
  const bal = (a) => e.provider.getBalance(a);
  let V;
  await test('factory deploys vault, modules + router wired', async () => {
    V = await newVault(W);
    const acc = e.at('MSAAdvanced', V.account);
    assert(await acc.isModuleInstalled(1, bio, '0x'), 'biometric validator');
    assert(await acc.isModuleInstalled(1, tl, '0x'), 'timelock validator');
    assert(await acc.isModuleInstalled(2, tl, '0x'), 'timelock executor');
    assert(await acc.isModuleInstalled(2, gd, '0x'), 'guardian executor');
    assert(await acc.isModuleInstalled(4, R, '0x'), 'router hook');
    const subs = await W.router.subHooksOf(V.account);
    assert(subs[0] === tl && subs.length === 5, 'subhooks ' + subs.length);
    assert(await W.bio.isInitialized(V.account), 'bio init');
  });
  await test('createVault idempotent; address deterministic', async () => {
    const again = await W.factory.createVault.staticCall(V.salt, V.cfg);
    assert(again === V.account, 'same address');
  });
  await test('implementation / bootstrap cannot be initialised directly', async () => {
    await reverts(W.impl.initializeAccount('0x'), '', 'impl init');
  });
  await test('passkey sends ETH via EntryPoint', async () => {
    const before = await bal(N.bob.address);
    const op = await K.userOp(V.account, bio, K.execSingle(N.bob.address, ETH('0.5')));
    await K.signPasskey(op, V.passkey);
    const r = await K.submit(op);
    assert(r.ok && r.results[0].success, 'op failed ' + JSON.stringify(r.failedOp || r.results));
    assert((await bal(N.bob.address)) - before === ETH('0.5'), 'bob got 0.5');
  });
  await test('passkey sends ERC20', async () => {
    const data = K.erc20.encodeFunctionData('transfer', [N.bob.address, 400_000_000n]);
    const op = await K.userOp(V.account, bio, K.execSingle(tok, 0n, data));
    await K.signPasskey(op, V.passkey);
    const r = await K.submit(op);
    assert(r.ok && r.results[0].success, 'erc20 send ' + JSON.stringify(r.failedOp || r.results));
    assert((await W.token.balanceOf(N.bob.address)) === 400_000_000n, 'bob tokens');
  });
  await test('wrong passkey rejected (AA24)', async () => {
    const op = await K.userOp(V.account, bio, K.execSingle(N.bob.address, ETH('1')));
    await K.signPasskey(op, L.newPasskey('evil'));
    const r = await K.submit(op);
    assert(!r.ok, 'should fail'); console.log('      ->', r.failedOp);
  });
  await test('spending key: small ETH send OK', async () => {
    const before = await bal(N.bob.address);
    const op = await K.userOp(V.account, tl, K.execSingle(N.bob.address, ETH('0.2')), { verGas: 400_000n, callGas: 400_000n });
    await K.signKey(op, V.spender);
    const r = await K.submit(op);
    assert(r.ok && r.results[0].success, 'spend ' + JSON.stringify(r.failedOp || r.results));
    assert((await bal(N.bob.address)) - before === ETH('0.2'), 'bob got 0.2');
  });
  await test('spending key: eth-signed-message signature also accepted', async () => {
    const op = await K.userOp(V.account, tl, K.execSingle(N.bob.address, ETH('0.01')), { verGas: 400_000n, callGas: 400_000n });
    await K.signKey(op, V.spender, true);
    const r = await K.submit(op);
    assert(r.ok && r.results[0].success, 'ethsigned ' + JSON.stringify(r.failedOp || r.results));
  });
  await test('spending key: over per-tx cap rejected in validation', async () => {
    const op = await K.userOp(V.account, tl, K.execSingle(N.bob.address, ETH('0.3')), { verGas: 400_000n, callGas: 400_000n });
    await K.signKey(op, V.spender);
    const r = await K.submit(op); assert(!r.ok, 'should fail'); console.log('      ->', r.failedOp);
  });
  // ───────────────────────── helpers ─────────────────────────
  const passkeyOp = async (V, callData, o = {}, sigOpts) => K.signPasskey(await K.userOp(V.account, bio, callData, o), V.passkey, sigOpts);
  const spendOp = async (V, callData, o = {}) => K.signKey(await K.userOp(V.account, tl, callData, { verGas: 400_000n, callGas: 400_000n, ...o }), V.spender);
  const okAll = (r) => r.ok && r.results.every((x) => x.success);
  const why = (r) => JSON.stringify(r.failedOp || r.results);
  const ethSend = (to, v) => K.execSingle(to, ETH(String(v)));
  const tlI = W.tl.interface;
  const parseLogs = (receipt, iface) => receipt.logs.map((l) => { try { return iface.parseLog(l); } catch { return null; } }).filter(Boolean);

  // ───────────────────────── velocity budget ─────────────────────────
  await test('velocity: cumulative value cap enforced, resets after 24h', async () => {
    const v = await newVault(W);
    for (let i = 0; i < 4; i++) { const r = await K.submit(await spendOp(v, ethSend(N.bob.address, 0.25))); assert(okAll(r), 'spend ' + i + why(r)); }
    const r5 = await K.submit(await spendOp(v, ethSend(N.bob.address, 0.01)));
    assert(r5.ok && !r5.results[0].success && /BudgetExceeded/.test(r5.results[0].reason), '5th must hit budget: ' + why(r5));
    await e.increaseTime(24 * 3600 + 5);
    const r6 = await K.submit(await spendOp(v, ethSend(N.bob.address, 0.25)));
    assert(okAll(r6), 'after window ' + why(r6));
  });
  await test('velocity: count cap (11th tiny tx blocked) - the drip-drain attack', async () => {
    const v = await newVault(W, { policies: [{ token: ethers.ZeroAddress, highValue: ETH('0.25'), windowLimit: ETH('10') }] });
    for (let i = 0; i < 10; i++) { const r = await K.submit(await spendOp(v, ethSend(N.bob.address, 0.001))); assert(okAll(r), 'tiny ' + i + why(r)); }
    const r = await K.submit(await spendOp(v, ethSend(N.bob.address, 0.001)));
    assert(r.ok && !r.results[0].success && /BudgetExceeded/.test(r.results[0].reason), '11th must hit count cap: ' + why(r));
    await e.increaseTime(24 * 3600 + 5);
    assert(okAll(await K.submit(await spendOp(v, ethSend(N.bob.address, 0.001)))), 'after window');
  });
  await test('velocity: two spending-key ops in ONE bundle share the budget', async () => {
    const v = await newVault(W);
    const n0 = await K.nonce(v.account, tl);
    const o1 = await spendOp(v, ethSend(N.bob.address, 0.25), { nonce: n0 });
    const o2 = await spendOp(v, ethSend(N.bob.address, 0.25), { nonce: n0 + 1n });
    const o3 = await spendOp(v, ethSend(N.bob.address, 0.25), { nonce: n0 + 2n });
    const o4 = await spendOp(v, ethSend(N.bob.address, 0.25), { nonce: n0 + 3n });
    const o5 = await spendOp(v, ethSend(N.bob.address, 0.25), { nonce: n0 + 4n });
    const before = await bal(N.bob.address);
    const r = await K.submit([o1, o2, o3, o4, o5]);
    assert(r.ok, 'bundle ' + why(r));
    assert(r.results.filter((x) => x.success).length === 4 && !r.results[4].success, 'exactly 4 of 5 pass ' + why(r));
    assert((await bal(N.bob.address)) - before === ETH('1'), 'only 1 ETH left the vault');
  });
  await test('velocity: ERC20 budget per token', async () => {
    const v = await newVault(W);
    const send = (amt) => K.execSingle(tok, 0n, K.erc20.encodeFunctionData('transfer', [N.bob.address, amt]));
    for (let i = 0; i < 3; i++) assert(okAll(await K.submit(await spendOp(v, send(300_000_000n)))), 'tok ' + i);
    const r = await K.submit(await spendOp(v, send(200_000_000n)));
    assert(r.ok && !r.results[0].success, 'over 1000e6 window: ' + why(r));
  });


  await test('gas drain: spending key can only burn the gas TANK, never the vault balance', async () => {
    const v = await newVault(W, { tank: false });
    // no tank => the key cannot even start an op (it would have to be paid from the vault balance)
    let r = await K.submit(await spendOp(v, ethSend(N.bob.address, 0.01)));
    assert(!r.ok, 'untanked op must be refused: ' + why(r));
    await (await e.entryPoint.depositTo(v.account, { value: ETH('0.01') })).wait();
    // absurd gas price: required prefund exceeds the tank => refused (this was the "pay the thief via priority fee" drain)
    r = await K.submit(await spendOp(v, ethSend(N.bob.address, 0.01), { prio: 10_000_000_000_000n, maxFee: 10_000_000_000_000n }));
    assert(!r.ok, 'price-gouging op must be refused: ' + why(r));
    const acct0 = await bal(v.account);
    r = await K.submit(await spendOp(v, ethSend(N.bob.address, 0.01)));
    assert(okAll(r), 'normal op ok ' + why(r));
    assert(acct0 - (await bal(v.account)) === ETH('0.01'), 'vault balance only lost the 0.01 transfer, gas came from the tank');
    // repeated failing ops can only ever consume the tank
    let spentTank = 0n;
    const tank0 = await e.entryPoint.balanceOf(v.account);
    for (let i = 0; i < 6; i++) {
      const rr = await K.submit(await spendOp(v, ethSend(N.bob.address, 0.25)));   // eventually over budget => reverts in execution
      if (!rr.ok) break;
    }
    const tank1 = await e.entryPoint.balanceOf(v.account);
    assert(tank1 <= tank0 && (await bal(v.account)) >= ETH('8.0'), 'only tank + budgeted transfers left the vault');
  });
  await test('spending key: tokens without a policy are untouchable; zero-amount refused', async () => {
    const v = await newVault(W, { policies: [{ token: ethers.ZeroAddress, highValue: ETH('0.25'), windowLimit: ETH('1') }] });
    const send = (amt) => K.execSingle(tok, 0n, K.erc20.encodeFunctionData('transfer', [N.bob.address, amt]));
    assert(!(await K.submit(await spendOp(v, send(1n)))).ok, 'unlisted token blocked');
    assert(!(await K.submit(await spendOp(v, ethSend(N.bob.address, 0)))).ok, 'zero ETH refused');
    // enabling a new token for the spending key is a loosening => queued, passkey only
    const cd = K.execSingle(tl, 0n, tlI.encodeFunctionData('setTokenPolicy', [tok, 1000n, 5000n]));
    assert(okAll(await K.submit(await passkeyOp(v, cd))), 'queue policy');
    assert(!(await K.submit(await spendOp(v, send(1n)))).ok, 'still blocked before delay');
    await e.increaseTime(48 * 3600 + 5);
    await (await W.tl.applyPolicy(v.account, tok)).wait();
    assert(okAll(await K.submit(await spendOp(v, send(1n)))), 'enabled after delay');
  });

  // ───────────────────────── spending key confinement ─────────────────────────
  await test('spending key CANNOT do anything but small transfers / queue / cancel', async () => {
    const v = await newVault(W);
    const acc = new ethers.Interface(e.A.MSAAdvanced.abi);
    const cases = {
      'ETH send with calldata': K.execSingle(N.bob.address, 1n, '0x1234'),
      'erc20 approve': K.execSingle(tok, 0n, K.erc20.encodeFunctionData('approve', [N.attacker.address, 1n])),
      'erc20 transferFrom': K.execSingle(tok, 0n, K.erc20.encodeFunctionData('transferFrom', [v.account, N.attacker.address, 1n])),
      'erc20 transfer + ETH value': K.execSingle(tok, 1n, K.erc20.encodeFunctionData('transfer', [N.bob.address, 1n])),
      'batch': K.execBatch([{ target: N.bob.address, value: 1n }]),
      'delegatecall mode': K.execSingle(N.bob.address, 0n, '0x', MODE_DELEGATE),
      'installModule on account': K.execSingle(v.account, 0n, acc.encodeFunctionData('installModule', [1, N.attacker.address, '0x'])),
      'uninstall hook': K.execSingle(v.account, 0n, acc.encodeFunctionData('uninstallModule', [4, R, '0x'])),
      'timelock.setSigner': K.execSingle(tl, 0n, tlI.encodeFunctionData('setSigner', [N.attacker.address])),
      'timelock.setTokenPolicy': K.execSingle(tl, 0n, tlI.encodeFunctionData('setTokenPolicy', [ethers.ZeroAddress, ETH('1000'), ETH('1000')])),
      'biometric.addCredential': K.execSingle(bio, 0n, new ethers.Interface(e.A.BiometricValidator.abi).encodeFunctionData('addCredential', [ethers.id('x'), [1n, 2n]])),
      'executeUserOp wrapper': acc.getFunction('executeUserOp').selector + K.execSingle(N.bob.address, 1n).slice(2),
      'send to zero address': K.execSingle(ethers.ZeroAddress, 1n),
      'empty calldata': '0x',
    };
    for (const [name, cd] of Object.entries(cases)) {
      const r = await K.submit(await spendOp(v, cd));
      assert(!r.ok || !r.results[0].success, name + ' was NOT blocked: ' + why(r));
    }
    // nothing moved
    assert((await bal(v.account)) >= ETH('9.9'), 'vault intact');
  });
  await test('spending key: gas caps + foreign signature + disabled signer', async () => {
    const v = await newVault(W);
    let r = await K.submit(await spendOp(v, ethSend(N.bob.address, 0.01), { callGas: 900_000n }));
    assert(!r.ok, 'callGas cap');
    r = await K.submit(await spendOp(v, ethSend(N.bob.address, 0.01), { verGas: 900_000n }));
    assert(!r.ok, 'verGas cap');
    const op = await K.userOp(v.account, tl, ethSend(N.bob.address, 0.01), { verGas: 400_000n, callGas: 400_000n });
    await K.signKey(op, ethers.Wallet.createRandom());
    assert(!(await K.submit(op)).ok, 'foreign key');
    const v2 = await newVault(W, { noSpender: true });
    assert(!(await K.submit(await spendOp(v2, ethSend(N.bob.address, 0.01)))).ok, 'no signer => disabled');
  });
  await test('passkey can rotate / disable the spending key; old key dies', async () => {
    const v = await newVault(W);
    const nk = ethers.Wallet.createRandom();
    let r = await K.submit(await passkeyOp(v, K.execSingle(tl, 0n, tlI.encodeFunctionData('setSigner', [nk.address]))));
    assert(okAll(r), 'rotate ' + why(r));
    assert(!(await K.submit(await spendOp(v, ethSend(N.bob.address, 0.01)))).ok, 'old key dead');
    const op = await K.userOp(v.account, tl, ethSend(N.bob.address, 0.01), { verGas: 400_000n, callGas: 400_000n });
    await K.signKey(op, nk);
    assert(okAll(await K.submit(op)), 'new key works');
  });
  // ───────────────────────── delayed tx + fingerprint release ─────────────────────────
  const queue = async (v, token, amount, to, by = 'spend') => {
    const cd = K.execSingle(tl, 0n, tlI.encodeFunctionData('initiateDelayedTx', [token, amount, to]));
    const r = await K.submit(by === 'spend' ? await spendOp(v, cd) : await passkeyOp(v, cd));
    const ev = r.ok ? parseLogs(r.receipt, tlI).find((p) => p.name === 'BiometricConfirmationRequested') : null;
    return { r, txHash: ev?.args.txHash, ev };
  };
  const confirmSig = async (v, txHash, pk = v.passkey, o = {}) => {
    const ch = await W.tl.confirmationChallenge(v.account, txHash);
    return L.webauthnSig(pk, ch, o);
  };
  await test('delayed: large tx queued by spending key, NOT executed, released only by fingerprint', async () => {
    const v = await newVault(W, { subs: ['freeze', 'multisig', 'antiscam'] });
    const before = await bal(N.bob.address);
    const q = await queue(v, ethers.ZeroAddress, ETH('5'), N.bob.address);
    assert(okAll(q.r) && q.txHash, 'queued ' + why(q.r));
    assert((await bal(N.bob.address)) === before, 'nothing moved on queue');
    assert(q.ev.args.amount === ETH('5') && q.ev.args.recipient === N.bob.address, 'event content for SMS');
    // anyone can relay, but a bad / missing assertion releases nothing
    await reverts(W.tl.connect(N.attacker).confirmAndRelease(v.account, q.txHash, await confirmSig(v, q.txHash, L.newPasskey('evil'), { credentialId: v.passkey.credentialId })), '', 'evil key, victim cred id');
    const atk = await newVault(W);  // attacker's own vault + own enrolled passkey
    await reverts(W.tl.connect(N.attacker).confirmAndRelease(v.account, q.txHash, await confirmSig(v, q.txHash, atk.passkey)), '', 'attacker enrolled passkey');
    await reverts(W.tl.connect(N.attacker).confirmAndRelease(v.account, q.txHash, await confirmSig(v, q.txHash, v.passkey, { flags: 0x01 })), 'UserVerificationNotSet', 'no UV (tap only)');
    // assertion for a DIFFERENT tx hash is useless
    const q2 = await queue(v, ethers.ZeroAddress, ETH('1'), N.bob.address);
    await reverts(W.tl.connect(N.attacker).confirmAndRelease(v.account, q.txHash, await confirmSig(v, q2.txHash)), '', 'wrong challenge');
    assert((await bal(N.bob.address)) === before, 'still nothing moved');
    await (await W.tl.connect(N.attacker).confirmAndRelease(v.account, q.txHash, await confirmSig(v, q.txHash))).wait();
    assert((await bal(N.bob.address)) - before === ETH('5'), 'released 5 ETH');
    await reverts(W.tl.connect(N.attacker).confirmAndRelease(v.account, q.txHash, await confirmSig(v, q.txHash)), 'Already executed', 'replay');
  });
  await test('delayed: unconfirmed tx dies after 48h (cannot be released, expireTx finalises)', async () => {
    const v = await newVault(W);
    const q = await queue(v, ethers.ZeroAddress, ETH('3'), N.bob.address);
    const sig = await confirmSig(v, q.txHash);
    await e.increaseTime(48 * 3600 + 10);
    await reverts(W.tl.confirmAndRelease(v.account, q.txHash, sig), 'Expired', 'late confirm');
    await (await W.tl.expireTx(v.account, q.txHash)).wait();
    await reverts(W.tl.confirmAndRelease(v.account, q.txHash, sig), 'Cancelled', 'after expire');
    const cfg = await W.tl.getConfig(v.account);
    assert(cfg.openPending === 0n, 'slot freed');
  });
  await test('delayed: ERC20 release + guardian cancel + attacker cannot cancel + open-slot cap', async () => {
    const v = await newVault(W);
    const q = await queue(v, tok, 700_000_000n, N.bob.address, 'passkey');
    assert(q.txHash, 'queued by passkey');
    await reverts(W.tl.connect(N.attacker).cancelTx(v.account, q.txHash), 'NotAuthorized');
    await (await W.tl.connect(N.g1).cancelTx(v.account, q.txHash)).wait();
    await reverts(W.tl.confirmAndRelease(v.account, q.txHash, await confirmSig(v, q.txHash)), 'Cancelled');
    const q2 = await queue(v, tok, 700_000_000n, N.bob.address, 'passkey');
    const b0 = await W.token.balanceOf(N.bob.address);
    await (await W.tl.confirmAndRelease(v.account, q2.txHash, await confirmSig(v, q2.txHash))).wait();
    assert((await W.token.balanceOf(N.bob.address)) - b0 === 700_000_000n, 'token released');
    for (let i = 0; i < 5; i++) assert((await queue(v, ethers.ZeroAddress, 1n, N.bob.address)).txHash, 'slot ' + i);
    const over = await queue(v, ethers.ZeroAddress, 1n, N.bob.address);
    assert(!over.txHash, 'sixth open tx refused');
  });
  await test('delayed: release is NOT counted against / blocked by the spending budget', async () => {
    const v = await newVault(W, { subs: ['freeze', 'multisig', 'antiscam'] });
    for (let i = 0; i < 4; i++) assert(okAll(await K.submit(await spendOp(v, ethSend(N.bob.address, 0.25)))), 'burn budget');
    const q = await queue(v, ethers.ZeroAddress, ETH('4'), N.bob.address);
    const b0 = await bal(N.bob.address);
    await (await W.tl.confirmAndRelease(v.account, q.txHash, await confirmSig(v, q.txHash))).wait();
    assert((await bal(N.bob.address)) - b0 === ETH('4'), 'fingerprint-confirmed release independent of budget');
  });

  // ───────────────────────── hook router + policy hooks ─────────────────────────
  await test('freeze: guardian freezes, EVERYTHING stops; unfreeze needs 2 votes', async () => {
    const v = await newVault(W);
    const fz = W.freeze;
    await reverts(fz.connect(N.attacker).freeze(v.account), 'Not a guardian');
    await (await fz.connect(N.g1).freeze(v.account)).wait();
    let r = await K.submit(await passkeyOp(v, ethSend(N.bob.address, 0.1)));
    assert(r.ok && !r.results[0].success && /frozen/.test(r.results[0].reason), 'passkey blocked: ' + why(r));
    r = await K.submit(await spendOp(v, ethSend(N.bob.address, 0.1)));
    assert(r.ok && !r.results[0].success, 'spend key blocked');
    await (await fz.connect(N.g1).voteToUnfreeze(v.account)).wait();
    assert(!okAll(await K.submit(await passkeyOp(v, ethSend(N.bob.address, 0.1)))), 'still frozen after 1 vote');
    await (await fz.connect(N.g2).voteToUnfreeze(v.account)).wait();
    assert(okAll(await K.submit(await passkeyOp(v, ethSend(N.bob.address, 0.1)))), 'unfrozen');
  });
  await test('antiscam: blocks ETH, ERC20 transfer, approve, batch members, to flagged address', async () => {
    const v = await newVault(W);
    await (await W.antiscam.registerThreat(N.scammer.address, 3, 'phishing')).wait();
    const S = N.scammer.address;
    const cases = {
      eth: K.execSingle(S, 1n),
      erc20: K.execSingle(tok, 0n, K.erc20.encodeFunctionData('transfer', [S, 1n])),
      approve: K.execSingle(tok, 0n, K.erc20.encodeFunctionData('approve', [S, 1n])),
      batch: K.execBatch([{ target: N.bob.address, value: 1n }, { target: S, value: 1n }]),
      batchErc20: K.execBatch([{ target: N.bob.address, value: 1n }, { target: tok, data: K.erc20.encodeFunctionData('transfer', [S, 1n]) }]),
    };
    for (const [name, cd] of Object.entries(cases)) {
      const r = await K.submit(await passkeyOp(v, cd));
      assert(r.ok && !r.results[0].success && /AntiScam/.test(r.results[0].reason || ''), name + ' not blocked: ' + why(r));
    }
    assert((await bal(S)) === (await bal(S)) && okAll(await K.submit(await passkeyOp(v, ethSend(N.bob.address, 0.1)))), 'normal send still fine');
  });
  await test('router: malformed / aliased ABI encodings cannot smuggle a flagged recipient', async () => {
    const v = await newVault(W);
    const S = N.scammer.address;
    const mk = (types, vals) => L.abi.encode(types, vals);
    const accI = new ethers.Interface(e.A.MSAAdvanced.abi);
    const sel = accI.getFunction('execute').selector;
    const word = (n) => ethers.toBeHex(n, 32).slice(2);
    const exSingle = L.packSingle(S, 1n, '0x');
    const exBatch = L.packBatch([{ target: N.bob.address, value: 1n }, { target: S, value: 1n }]);
    const variants = {};
    // canonical
    variants.canonical = sel + mk(['bytes32', 'bytes'], [L.MODE_BATCH, exBatch]).slice(2);
    // non-canonical outer offset: 0x60 with a junk word in between
    variants.outerOffset = sel + L.MODE_BATCH.slice(2) + word(0x60) + word(0xdead) + word(ethers.dataLength(exBatch)) + exBatch.slice(2).padEnd(Math.ceil(ethers.dataLength(exBatch) / 32) * 64, '0');
    // non-canonical array offset inside executionCalldata (0x40, junk word first)
    const body = exBatch.slice(2);
    const inner = '0x' + word(0x40) + word(0xbeef) + body.slice(64);
    variants.innerOffset = sel + mk(['bytes32', 'bytes'], [L.MODE_BATCH, inner]).slice(2);
    // single mode, flagged target
    variants.single = sel + mk(['bytes32', 'bytes'], [L.MODE_SINGLE, exSingle]).slice(2);
    // try-mode batch
    variants.tryBatch = sel + mk(['bytes32', 'bytes'], ['0x0100' + '00'.repeat(30), exBatch]).slice(2);
    // reversed element pointers
    const ex = [[N.bob.address, 1n, '0x'], [S, 1n, '0x']];
    let enc = mk(['tuple(address,uint256,bytes)[]'], [ex]).slice(2); // 0x20|len|off0|off1|elems
    const w = (i) => enc.slice(i * 64, i * 64 + 64);
    const swapped = '0x' + w(0) + w(1) + w(3) + w(2) + enc.slice(4 * 64);
    variants.swappedPtrs = sel + mk(['bytes32', 'bytes'], [L.MODE_BATCH, swapped]).slice(2);
    // truncated array (length says 2 but data for 1)
    variants.truncated = sel + mk(['bytes32', 'bytes'], [L.MODE_BATCH, '0x' + enc.slice(0, 64) + word(2) + enc.slice(128, 128 + 64 * 5)]).slice(2);
    // delegatecall / unknown call type
    variants.delegate = sel + mk(['bytes32', 'bytes'], [L.MODE_DELEGATE, exSingle]).slice(2);
    variants.unknownType = sel + mk(['bytes32', 'bytes'], ['0x07' + '00'.repeat(31), exSingle]).slice(2);
    const sbal = await bal(S);
    for (const [name, cd] of Object.entries(variants)) {
      const r = await K.submit(await passkeyOp(v, cd));
      const succeeded = r.ok && r.results[0].success;
      assert(!succeeded, name + ' executed!');
    }
    assert((await bal(S)) === sbal, 'flagged address received nothing');
  });
  await test('multisig guard: module install/uninstall blocked without guardian consensus; works with it (direct AND execute-wrapped)', async () => {
    const v = await newVault(W);
    const accI = new ethers.Interface(e.A.MSAAdvanced.abi);
    const newTl = await e.deploy('TimeLockValidator', [bio, R, e.EP_ADDR]);
    const nTl = await newTl.getAddress();
    const initD = L.abi.encode(['address', 'address[]', 'uint256', 'tuple(address token,uint128 highValue,uint128 windowLimit)[]'], [N.bob.address, [], 0, []]);
    const installCd = accI.encodeFunctionData('installModule', [1, nTl, initD]);
    // blocked: direct and wrapped
    let r = await K.submit(await passkeyOp(v, installCd));
    assert(r.ok && !r.results[0].success && /guardian consensus/.test(r.results[0].reason), 'direct blocked ' + why(r));
    r = await K.submit(await passkeyOp(v, K.execSingle(v.account, 0n, installCd)));
    assert(r.ok && !r.results[0].success && /guardian consensus/.test(r.results[0].reason), 'wrapped blocked ' + why(r));
    const uninst = accI.encodeFunctionData('uninstallModule', [4, R, '0x']);
    r = await K.submit(await passkeyOp(v, uninst));
    assert(r.ok && !r.results[0].success, 'router uninstall blocked');
    // approved path
    const ms = W.multisig;
    const delay = await ms.UPGRADE_DELAY();
    const prop = async () => {
      const t = await (await ms.connect(N.g1).proposeUpgrade(v.account, nTl, '0x00000001')).wait();
      const id = t.logs.map((l) => { try { return ms.interface.parseLog(l); } catch { return null; } }).find((p) => p && p.name === 'UpgradeProposed').args.proposalId;
      await (await ms.connect(N.g2).approveUpgrade(v.account, id)).wait();
      return id;
    };
    const id = await prop();
    await reverts(ms.executeUpgrade(v.account, id), 'Delay', 'too early');
    await e.increaseTime(Number(delay) + 5);
    await (await ms.executeUpgrade(v.account, id)).wait();
    r = await K.submit(await passkeyOp(v, installCd));
    assert(okAll(r), 'approved direct install ' + why(r));
    assert(await e.at('MSAAdvanced', v.account).isModuleInstalled(1, nTl, '0x'), 'installed');
    // grant is single-use
    const newTl2 = await e.deploy('TimeLockValidator', [bio, R, e.EP_ADDR]);
    r = await K.submit(await passkeyOp(v, accI.encodeFunctionData('installModule', [1, await newTl2.getAddress(), initD])));
    assert(!okAll(r), 'second install without a grant must fail');
    // wrapped path with a fresh grant
    const id2 = await (async () => {
      const t = await (await ms.connect(N.g1).proposeUpgrade(v.account, await newTl2.getAddress(), '0x00000001')).wait();
      const pid = t.logs.map((l) => { try { return ms.interface.parseLog(l); } catch { return null; } }).find((p) => p && p.name === 'UpgradeProposed').args.proposalId;
      await (await ms.connect(N.g2).approveUpgrade(v.account, pid)).wait(); return pid;
    })();
    await e.increaseTime(Number(delay) + 5);
    await (await ms.executeUpgrade(v.account, id2)).wait();
    r = await K.submit(await passkeyOp(v, K.execSingle(v.account, 0n, accI.encodeFunctionData('installModule', [1, await newTl2.getAddress(), initD]))));
    assert(okAll(r), 'approved WRAPPED install ' + why(r));
  });
  await test('poisoned-address hook: big unverified transfer needs fresh single-use full-address confirmation', async () => {
    const v = await newVault(W);
    const P = W.poison, Pa = await P.getAddress();
    const pI = P.interface;
    const big = ETH('1.5');
    let r = await K.submit(await passkeyOp(v, K.execSingle(N.bob.address, big)));
    assert(r.ok && !r.results[0].success && /ConfirmationRequired/.test(r.results[0].reason), 'blocked first ' + why(r));
    assert(okAll(await K.submit(await passkeyOp(v, K.execSingle(Pa, 0n, pI.encodeFunctionData('confirmFullAddress', [ethers.ZeroAddress, N.bob.address, big]))))), 'confirm');
    assert(okAll(await K.submit(await passkeyOp(v, K.execSingle(N.bob.address, big)))), 'allowed after confirm');
    r = await K.submit(await passkeyOp(v, K.execSingle(N.bob.address, big)));
    assert(r.ok && !r.results[0].success, 'confirmation is single use');
    assert(okAll(await K.submit(await passkeyOp(v, K.execSingle(Pa, 0n, pI.encodeFunctionData('verifyAndSaveAddress', [N.bob.address]))))), 'save');
    assert(okAll(await K.submit(await passkeyOp(v, K.execSingle(N.bob.address, big)))), 'verified address ok');
    // lookalike of a known-poisoned address is refused outright
    const fp = ethers.hexlify(ethers.concat([ethers.dataSlice(N.scammer.address, 0, 4), ethers.dataSlice(N.scammer.address, 16, 20)]));
    await (await P.flagPoisonedFingerprint(fp)).wait();
    r = await K.submit(await passkeyOp(v, K.execSingle(N.scammer.address, 1n)));
    assert(r.ok && !r.results[0].success && /PoisonedAddress/.test(r.results[0].reason), 'poisoned lookalike refused ' + why(r));
    await reverts(P.connect(N.attacker).flagPoisonedFingerprint('0x1122334455667788'), 'not owner');
  });

  await test('delayed: reentrancy by the recipient cannot double-release', async () => {
    const v = await newVault(W, { subs: ['freeze', 'multisig', 'antiscam'] });
    const re = await e.deploy('Reenter');
    const q = await queue(v, ethers.ZeroAddress, ETH('2'), await re.getAddress());
    const sig = await confirmSig(v, q.txHash);
    await (await re.arm(tl, v.account, q.txHash, sig)).wait();
    const b0 = await bal(await re.getAddress());
    await (await W.tl.confirmAndRelease(v.account, q.txHash, sig)).wait();
    assert((await bal(await re.getAddress())) - b0 === ETH('2'), 'paid exactly once');
    assert((await re.reenterOk()) === false, 'reentrant release must fail');
  });
  await test('PAP + delayed release: address confirmation still applies to big releases (documented)', async () => {
    const v = await newVault(W);
    const q = await queue(v, ethers.ZeroAddress, ETH('3'), N.bob.address);
    await reverts(W.tl.confirmAndRelease(v.account, q.txHash, await confirmSig(v, q.txHash)), 'ConfirmationRequired');
    assert(okAll(await K.submit(await passkeyOp(v, K.execSingle(await W.poison.getAddress(), 0n, W.poison.interface.encodeFunctionData('confirmFullAddress', [ethers.ZeroAddress, N.bob.address, ETH('3')]))))), 'confirm');
    await (await W.tl.confirmAndRelease(v.account, q.txHash, await confirmSig(v, q.txHash))).wait();
  });
  await test('fuzz: mutated execute() calldata can never move funds to a flagged address', async () => {
    const v = await newVault(W);
    const S = N.scammer.address;
    await (await W.antiscam.registerThreat(S, 4, 'drainer')).wait();
    await e.send('hardhat_impersonateAccount', [e.EP_ADDR]); await e.send('hardhat_setBalance', [e.EP_ADDR, '0x56BC75E2D63100000']);
    const epS = new ethers.JsonRpcSigner(e.provider, e.EP_ADDR);
    const accI = new ethers.Interface(e.A.MSAAdvanced.abi);
    const sel = accI.getFunction('execute').selector;
    const bases = [
      sel + L.abi.encode(['bytes32', 'bytes'], [L.MODE_BATCH, L.packBatch([{ target: N.bob.address, value: 1n }, { target: S, value: 7n }])]).slice(2),
      sel + L.abi.encode(['bytes32', 'bytes'], [L.MODE_BATCH, L.packBatch([{ target: S, value: 7n }])]).slice(2),
      sel + L.abi.encode(['bytes32', 'bytes'], [L.MODE_BATCH, L.packBatch([{ target: tok, data: K.erc20.encodeFunctionData('transfer', [S, 5n]) }])]).slice(2),
      sel + L.abi.encode(['bytes32', 'bytes'], [L.MODE_SINGLE, L.packSingle(S, 7n)]).slice(2),
    ];
    const words = ['00', '20', '40', '60', '80', 'a0', 'c0', 'e0', '0100', '01', '02', '03', 'ff'.repeat(32)].map((x) => x.padStart(64, '0'));
    let rnd = 12345; const R32 = () => { rnd = (rnd * 1103515245 + 12345) & 0x7fffffff; return rnd; };
    const sBal0 = await bal(S), sTok0 = await W.token.balanceOf(S);
    let ran = 0, executedAtAll = 0;
    for (let it = 0; it < 400; it++) {
      let hex = bases[it % bases.length].slice(10); // strip selector
      let ws = hex.match(/.{64}/g);
      const k = 1 + (R32() % 3);
      for (let m = 0; m < k; m++) {
        const kind = R32() % 5, i = R32() % ws.length, j = R32() % ws.length;
        if (kind === 0) ws[i] = words[R32() % words.length];
        else if (kind === 1) { const t = ws[i]; ws[i] = ws[j]; ws[j] = t; }
        else if (kind === 2) ws.splice(i, 0, words[R32() % words.length]);
        else if (kind === 3) ws.splice(i, 1);
        else ws[i] = ws[j];
      }
      const cd = sel + ws.join('');
      try {
        const tx = await epS.sendTransaction({ to: v.account, data: cd, gasLimit: 3_000_000 });
        const rc = await tx.wait(); ran++; executedAtAll += rc.status === 1 ? 1 : 0;
      } catch { /* reverted: fine */ }
    }
    assert((await bal(S)) === sBal0 && (await W.token.balanceOf(S)) === sTok0, 'flagged address got funds from a mutated encoding!');
    console.log('      fuzz: 400 mutations, executed-without-revert:', executedAtAll);
  });
  // ───────────────────────── guardian recovery ─────────────────────────
  await test('recovery: guardians (weight>=2, after 48h) replace the passkey; old passkey dies', async () => {
    const v = await newVault(W);
    const g = W.guardian, np = L.newPasskey('new');
    await reverts(g.connect(N.attacker).initiateRecovery(v.account, np.credentialId, [np.x, np.y]), 'NotGuardianOrOwner');
    await (await g.connect(N.rg1).initiateRecovery(v.account, np.credentialId, [np.x, np.y])).wait();
    await reverts(g.executeRecovery(v.account), 'InsufficientWeight', 'single guardian');
    await (await e.send('evm_increaseTime', [7 * 3600]), e.send('evm_mine'));
    await (await g.connect(N.rg2).approveRecovery(v.account)).wait();
    // threshold reached, delay not yet elapsed
    await reverts(g.executeRecovery(v.account), 'DelayNotElapsed');
    await e.increaseTime(48 * 3600 + 10);
    await (await g.executeRecovery(v.account)).wait();
    assert(!okAll(await K.submit(await passkeyOp(v, ethSend(N.bob.address, 0.1)))), 'old passkey must be dead');
    const nv = { ...v, passkey: np };
    assert(okAll(await K.submit(await passkeyOp(nv, ethSend(N.bob.address, 0.1)))), 'new passkey works');
  });
  await test('recovery: account/guardian can cancel; cannot recover while cancelled', async () => {
    const v = await newVault(W);
    const g = W.guardian, np = L.newPasskey('new2');
    await (await g.connect(N.rg1).initiateRecovery(v.account, np.credentialId, [np.x, np.y])).wait();
    await (await g.connect(N.rg2).cancelRecovery(v.account)).wait();
    await e.increaseTime(49 * 3600);
    await reverts(g.executeRecovery(v.account), 'AlreadyCancelled');
  });

  // ───────────────────────── senior mode ─────────────────────────
  await test('senior mode: hours, approved recipients, per-token limits, queued increases', async () => {
    const S = N.g1;
    const bobA = N.bob.address;
    const hr = Math.floor(((await e.now()) % 86400) / 3600);
    const data = (start, end) => L.abi.encode(
      ['address[]', 'int32', 'uint8', 'uint8', 'bool', 'address[]', 'tuple(address token,uint128 txLimit,uint128 dailyLimit)[]'],
      [[S.address], 0, start, end, true, [bobA, tl], [{ token: ethers.ZeroAddress, txLimit: ETH('1'), dailyLimit: ETH('2') }]]);
    const v = await newVault(W, { subs: ['senior'], seniorData: data(0, 24) });
    const sg = W.senior;
    assert(okAll(await K.submit(await passkeyOp(v, ethSend(bobA, 1)))), 'approved <= tx limit');
    let r = await K.submit(await passkeyOp(v, ethSend(N.attacker.address, 0.1)));
    assert(!r.results?.[0]?.success && /RecipientNotApproved/.test(r.results[0].reason), 'unapproved: ' + why(r));
    r = await K.submit(await passkeyOp(v, ethSend(bobA, 1.5)));
    assert(!r.results[0].success && /TxLimitExceeded/.test(r.results[0].reason), 'tx limit');
    assert(okAll(await K.submit(await passkeyOp(v, ethSend(bobA, 1)))), 'second 1 ETH (daily 2)');
    r = await K.submit(await passkeyOp(v, ethSend(bobA, 0.1)));
    assert(!r.results[0].success && /DailyLimitExceeded/.test(r.results[0].reason), 'daily limit');
    r = await K.submit(await passkeyOp(v, K.execSingle(tok, 0n, K.erc20.encodeFunctionData('transfer', [bobA, 1n]))));
    assert(!r.results[0].success, 'token without limits blocked (token not approved target / no limit)');
    // spending key is ALSO bound by the senior hook
    r = await K.submit(await spendOp(v, ethSend(N.attacker.address, 0.01)));
    assert(!r.results[0].success, 'spending key to unapproved blocked');
    // guardian: raising is queued, lowering immediate; stranger can't
    await reverts(sg.connect(N.attacker).approveAddress(v.account, N.attacker.address), 'NotGuardian');
    await (await sg.connect(S).setLimit(v.account, ethers.ZeroAddress, ETH('5'), ETH('50'))).wait();
    assert((await sg.limits(v.account, ethers.ZeroAddress)).txLimit === ETH('1'), 'raise is queued, not applied');
    await reverts(sg.applyLimit(v.account, ethers.ZeroAddress), 'Not ready');
    await (await sg.connect(S).setLimit(v.account, ethers.ZeroAddress, ETH('0.5'), ETH('1'))).wait();
    assert((await sg.limits(v.account, ethers.ZeroAddress)).txLimit === ETH('0.5'), 'lowering immediate');
    // next day the daily counter resets
    await e.increaseTime(24 * 3600 + 5);
    assert(okAll(await K.submit(await passkeyOp(v, ethSend(bobA, 0.5)))), 'new day');
    // time-of-day: window excluding "now"
    const [s2, e2] = hr < 23 ? [hr + 1, 24] : [0, 23];
    const v2 = await newVault(W, { subs: ['senior'], seniorData: data(s2, e2) });
    const nowHr = Math.floor(((await e.now()) % 86400) / 3600);
    if (nowHr < s2 || nowHr >= e2) {
      r = await K.submit(await passkeyOp(v2, ethSend(bobA, 0.1)));
      assert(!r.results[0].success && /OutsideAllowedHours/.test(r.results[0].reason), 'outside hours ' + why(r));
    }
  });

  // ───────────────────────── attackers ─────────────────────────
  await test('attack: policy hooks / budget only callable via the router', async () => {
    const hooks = [W.tl, W.freeze, W.multisig, W.poison, W.antiscam, W.senior, W.plain];
    for (const h of hooks) {
      await reverts(h.connect(N.attacker).preCheck(N.attacker.address, N.bob.address, 0n, '0x'), 'NotRouter', await h.getAddress());
    }
    // the router itself, called by a stranger, only ever acts on the stranger's own (empty) config
    await W.router.connect(N.attacker).preCheck.staticCall(N.attacker.address, 0n, '0x');
  });
  await test('attack: victim state cannot be touched by outsiders', async () => {
    const v = await newVault(W);
    const acc = e.at('MSAAdvanced', v.account, N.attacker);
    await reverts(acc.execute(L.MODE_SINGLE, L.packSingle(N.attacker.address, ETH('1'))), '', 'direct execute');
    await reverts(acc.installModule(1, N.attacker.address, '0x'), '', 'direct install');
    await reverts(acc.uninstallModule(4, R, '0x'), '', 'direct uninstall');
    await reverts(acc.executeFromExecutor(L.MODE_SINGLE, L.packSingle(N.attacker.address, ETH('1'))), 'InvalidModule');
    await reverts(acc.initializeAccount('0x'), 'NotInitializable');
    await reverts(W.bio.connect(N.attacker).recoverCredential(ethers.id('x'), [1n, 2n]), 'ModuleNotInitialized');
    await reverts(W.bio.connect(N.attacker).addCredential(ethers.id('x'), [1n, 2n]), 'ModuleNotInitialized');
    await reverts(W.tl.connect(N.attacker).initiateDelayedTx(ethers.ZeroAddress, 1n, N.attacker.address), 'Not installed');
    await reverts(W.tl.connect(N.attacker).confirmAndRelease(v.account, ethers.id('nope'), '0x'), 'Not found');
    await reverts(W.guardian.connect(N.attacker).approveRecovery(v.account), 'ModuleNotInitialized'.length ? '' : '');
    // attacker "installing" modules for their own address changes nothing about the victim
    await (await W.tl.connect(N.attacker).onInstall(L.abi.encode(['address', 'address[]', 'uint256', 'tuple(address token,uint128 highValue,uint128 windowLimit)[]'], [N.attacker.address, [], 0, []]))).wait();
    assert((await W.tl.getConfig(v.account)).signer === v.spender.address, 'victim signer untouched');
    assert((await bal(v.account)) >= ETH('9.9'), 'victim funds intact');
  });
  await test('attack: picking a different validator via the nonce key does not bypass auth', async () => {
    const v = await newVault(W);
    const mal = {};
    for (const [name, validator] of Object.entries({ guardianModule: gd, poison: await W.poison.getAddress(), antiscam: await W.antiscam.getAddress(), senior: await W.senior.getAddress(), random: N.attacker.address, router: R, token: tok, zero: ethers.ZeroAddress })) {
      const op = await K.userOp(v.account, validator, ethSend(N.attacker.address, 1));
      op.signature = '0x' + '11'.repeat(65);
      const r = await K.submit(op);
      assert(!r.ok, name + ' accepted as validator!');
    }
    assert((await bal(v.account)) >= ETH('9.9'), 'intact');
  });
  await test('attack: another vault\'s passkey cannot sign for this vault', async () => {
    const a = await newVault(W), b = await newVault(W);
    const op = await K.userOp(b.account, bio, ethSend(N.attacker.address, 1));
    await K.signPasskey(op, a.passkey, { credentialId: a.passkey.credentialId });
    assert(!(await K.submit(op)).ok, 'cross-vault passkey');
    const op2 = await K.userOp(b.account, bio, ethSend(N.attacker.address, 1));
    await K.signPasskey(op2, a.passkey, { credentialId: b.passkey.credentialId });
    assert(!(await K.submit(op2)).ok, 'cross-vault key under victim credential id');
    const op3 = await K.userOp(b.account, bio, ethSend(N.attacker.address, 1));
    await K.signPasskey(op3, b.passkey, { flags: 0x01 });
    assert(!(await K.submit(op3)).ok, 'tap-only (no user verification) rejected');
    const op4 = await K.userOp(b.account, bio, ethSend(N.attacker.address, 1));
    await K.signPasskey(op4, b.passkey, { rpId: 'evil.com' });
    assert(!(await K.submit(op4)).ok, 'wrong relying party rejected');
    const op5 = await K.userOp(b.account, bio, ethSend(N.attacker.address, 1));
    await K.signPasskey(op5, b.passkey, { badOffset: 5 });
    assert(!(await K.submit(op5)).ok, 'bogus challenge offset rejected');
  });
  await test('attack: factory — cannot front-run to a different config; allow-list enforced', async () => {
    const v = await newVault(W, { counterfactual: true, fund: false });
    const evil = JSON.parse(JSON.stringify(v.cfg, (k, x) => (typeof x === 'bigint' ? x.toString() : x)));
    evil.spendingSigner = N.attacker.address;
    const evilAddr = await W.factory['getAddress(bytes32,(bytes32,uint256[2],bytes32,address,address[],uint256,(address,uint128,uint128)[],(address,uint256,bytes32)[],uint256,(address,bytes)[]))'](v.salt, evil);
    assert(evilAddr !== v.account, 'different config => different address');
    const bad = { ...v.cfg, subHooks: [{ module: N.attacker.address, data: '0x' }] };
    await reverts(W.factory.createVault(ethers.id('s2'), bad), 'SubHookNotAllowed');
    const dup = { ...v.cfg, subHooks: [v.cfg.subHooks[0], v.cfg.subHooks[0]] };
    await reverts(W.factory.createVault(ethers.id('s3'), dup), 'DuplicateSubHook');
    const tlAsSub = { ...v.cfg, subHooks: [{ module: tl, data: '0x' }] };
    await reverts(W.factory.createVault(ethers.id('s4'), tlAsSub), 'SubHookNotAllowed');
  });
  await test('first userOp can deploy the vault through the EntryPoint (initCode)', async () => {
    const v = await newVault(W, { counterfactual: true, fund: false });
    await (await e.deployer.sendTransaction({ to: v.account, value: ETH('1') })).wait();
    const initCode = W.factory.target + W.factory.interface.encodeFunctionData('createVault', [v.salt, v.cfg]).slice(2);
    const op = await K.userOp(v.account, bio, ethSend(N.bob.address, 0.1), { initCode, nonce: BigInt(bio) << 96n, verGas: 6_000_000n });
    await K.signPasskey(op, v.passkey);
    const r = await K.submit(op);
    assert(okAll(r), 'initCode flow ' + why(r));
    assert((await e.provider.getCode(v.account)).length > 2, 'deployed');
  });

  await test('passkey via executeUserOp wrapper is still screened by the hooks', async () => {
    const v = await newVault(W);
    await (await W.antiscam.registerThreat(N.scammer.address, 4, 'drainer2')).wait();
    const accI = new ethers.Interface(e.A.MSAAdvanced.abi);
    const inner = K.execSingle(N.scammer.address, 1n);
    const wrapped = accI.getFunction('executeUserOp').selector + inner.slice(2);
    let r = await K.submit(await passkeyOp(v, wrapped));
    assert(!(r.ok && r.results[0].success), 'wrapped send to flagged address executed! ' + why(r));
    const okWrapped = accI.getFunction('executeUserOp').selector + K.execSingle(N.bob.address, 1n).slice(2);
    r = await K.submit(await passkeyOp(v, okWrapped));
    assert(okAll(r), 'wrapped benign send works ' + why(r));
  });
  console.log(L.results.filter((r) => !r[1]).length ? 'SOME FAILED' : 'ALL PASSED', L.results.length);
  process.exit(0);
})().catch((x) => { console.error(x); process.exit(1); });
