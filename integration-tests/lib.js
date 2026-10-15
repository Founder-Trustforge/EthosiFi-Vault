const crypto = require('crypto');
const { ethers } = require('ethers');
const abi = ethers.AbiCoder.defaultAbiCoder();
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

// ── passkey (WebAuthn P-256) ────────────────────────────────────────────────
function newPasskey(label = '') {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const x = BigInt('0x' + Buffer.from(jwk.x, 'base64url').toString('hex'));
  const y = BigInt('0x' + Buffer.from(jwk.y, 'base64url').toString('hex'));
  const credentialId = ethers.id('cred:' + label + ':' + crypto.randomBytes(8).toString('hex'));
  return { privateKey, x, y, credentialId };
}
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
function webauthnSig(pk, challenge32, o = {}) {
  const rpId = o.rpId || 'ethosifi.com';
  const flags = o.flags === undefined ? 0x05 : o.flags; // UP | UV
  const authData = Buffer.concat([sha256(rpId), Buffer.from([flags]), Buffer.from([0, 0, 0, 1])]);
  const chal = Buffer.from(ethers.getBytes(challenge32)).toString('base64url');
  const prefix = '{"type":"webauthn.get","challenge":"';
  const cd = Buffer.from(prefix + chal + '","origin":"https://' + rpId + '","crossOrigin":false}');
  const challengeOffset = prefix.length - '"challenge":"'.length + '"challenge":"'.length; // index just after `"challenge":"`
  const msg = Buffer.concat([authData, sha256(cd)]);
  const raw = crypto.sign('sha256', msg, { key: pk.privateKey, dsaEncoding: 'ieee-p1363' });
  let r = BigInt('0x' + raw.subarray(0, 32).toString('hex')), s = BigInt('0x' + raw.subarray(32).toString('hex'));
  if (s > N / 2n) s = N - s;
  return abi.encode(
    ['tuple(bytes authenticatorData, bytes clientDataJSON, uint256 challengeOffset, uint256[2] rs, bytes32 credentialId)'],
    [[authData, cd, o.badOffset ?? challengeOffset, [r, s], o.credentialId ?? pk.credentialId]]
  );
}

// ── account calldata ────────────────────────────────────────────────────────
const MODE_SINGLE = ethers.ZeroHash;
const MODE_BATCH = '0x01' + '00'.repeat(31);
const MODE_DELEGATE = '0xff' + '00'.repeat(31);
const MODE_TRY_SINGLE = '0x0001' + '00'.repeat(30);
const packSingle = (to, value, data = '0x') => ethers.solidityPacked(['address', 'uint256', 'bytes'], [to, value, data]);
const packBatch = (execs) => abi.encode(['tuple(address target,uint256 value,bytes callData)[]'], [execs.map((e) => [e.target, e.value ?? 0n, e.data ?? '0x'])]);

class Kit {
  constructor(env) {
    this.e = env;
    this.accIface = new ethers.Interface(env.A.MSAAdvanced.abi);
    this.erc20 = new ethers.Interface(env.A.MockToken.abi);
  }
  execSingle(to, value = 0n, data = '0x', mode = MODE_SINGLE) {
    return this.accIface.encodeFunctionData('execute', [mode, packSingle(to, value, data)]);
  }
  execBatch(execs, mode = MODE_BATCH) {
    return this.accIface.encodeFunctionData('execute', [mode, packBatch(execs)]);
  }
  async nonce(account, validator) {
    const key = BigInt(validator) << 32n; // 192-bit key; validator = top 160 bits of the 256-bit nonce
    return this.e.entryPoint.getNonce(account, key);
  }
  async userOp(account, validator, callData, o = {}) {
    return {
      sender: account,
      nonce: o.nonce ?? (await this.nonce(account, validator)),
      initCode: o.initCode ?? '0x',
      callData,
      accountGasLimits: ethers.solidityPacked(['uint128', 'uint128'], [o.verGas ?? 2_500_000n, o.callGas ?? 800_000n]),
      preVerificationGas: o.pvg ?? 100_000n,
      gasFees: ethers.solidityPacked(['uint128', 'uint128'], [o.prio ?? 1_000_000_000n, o.maxFee ?? 1_000_000_000n]),
      paymasterAndData: '0x',
      signature: '0x',
    };
  }
  async hash(op) { return this.e.entryPoint.getUserOpHash(op); }
  async signPasskey(op, pk, o) { op.signature = webauthnSig(pk, await this.hash(op), o); return op; }
  async signKey(op, wallet, ethSigned = false) {
    const h = await this.hash(op);
    op.signature = ethSigned ? await wallet.signMessage(ethers.getBytes(h)) : wallet.signingKey.sign(h).serialized;
    return op;
  }
  // Submit as the bundler; returns {ok, receipt, failedOp, results[]} where results[i] = {success, reason}
  async submit(ops, bundler) {
    const e = this.e; ops = Array.isArray(ops) ? ops : [ops];
    bundler = bundler || e.signers[1];
    const ep = e.entryPoint.connect(bundler);
    let tx;
    try { tx = await ep.handleOps(ops, bundler.address, { gasLimit: 12_000_000 }); }
    catch (err) { return { ok: false, failedOp: this.parseErr(err), err }; }
    const receipt = await tx.wait();
    const results = [];
    const epIface = e.entryPoint.interface;
    for (const l of receipt.logs) {
      let p; try { p = epIface.parseLog(l); } catch { continue; }
      if (!p) continue;
      if (p.name === 'UserOperationEvent') results.push({ success: p.args.success, sender: p.args.sender, reason: null });
      if (p.name === 'UserOperationRevertReason') {
        const r = results.find((x) => x.sender === p.args.sender && !x.success) || { sender: p.args.sender };
        r.reason = this.decodeRevert(p.args.revertReason);
        if (!results.includes(r)) results.push(r);
      }
    }
    // attach reasons by sender order (revert reason event is emitted before UserOperationEvent)
    const out = []; let pending = null;
    for (const l of receipt.logs) {
      let p; try { p = epIface.parseLog(l); } catch { continue; }
      if (!p) continue;
      if (p.name === 'UserOperationRevertReason') pending = this.decodeRevert(p.args.revertReason);
      if (p.name === 'UserOperationEvent') { out.push({ success: p.args.success, reason: p.args.success ? null : pending }); pending = null; }
    }
    return { ok: true, receipt, results: out };
  }
  decodeRevert(data) {
    try {
      if (data.startsWith('0x08c379a0')) return abi.decode(['string'], '0x' + data.slice(10))[0];
      return this.tryErrors(data);
    } catch { return data; }
  }
  tryErrors(data) {
    for (const k of this.e.errIfaces || []) { try { const d = k.parseError(data); if (d) return d.name + '(' + d.args.join(',') + ')'; } catch {} }
    return data;
  }
  parseErr(err) {
    const d = err.data || err.error?.data || err.info?.error?.data;
    try { const p = this.e.entryPoint.interface.parseError(d); if (p) return p.name + ':' + p.args.join('|'); } catch {}
    return err.shortMessage || err.message;
  }
}

// ── tiny test runner ────────────────────────────────────────────────────────
const results = [];
async function test(name, fn) {
  try { await fn(); results.push([name, true]); console.log('  PASS', name); }
  catch (e) { results.push([name, false, e]); console.log('  FAIL', name, '\n      ', (e.stack || e.message || String(e)).split('\n').slice(0, 4).join('\n       ')); }
}
const assert = (c, m) => { if (!c) throw new Error('assert: ' + m); };
let ERR_IFACES = null;
function errName(e) {
  const d = e.data || e.info?.error?.data || e.error?.data || e.revert?.data;
  if (typeof d === 'string' && d.startsWith('0x') && d.length >= 10) {
    ERR_IFACES = ERR_IFACES || Object.values(require(__dirname + '/artifacts.json')).map((a) => new ethers.Interface(a.abi));
    for (const i of ERR_IFACES) { try { const p = i.parseError(d); if (p) return p.name + '(' + p.args.join(',') + ')'; } catch {} }
  }
  return '';
}
async function reverts(p, frag, m = '') {
  try { await p; } catch (e) {
    const txt = [errName(e), e.shortMessage, e.message, e.reason, e.revert?.name, JSON.stringify(e.revert?.args ?? '')].join(' ');
    if (!frag || txt.includes(frag)) return;
    throw new Error('wrong revert (' + m + '): wanted "' + frag + '" got ' + txt.slice(0, 300));
  }
  throw new Error('expected revert ' + (frag || '') + ' ' + m);
}
module.exports = { newPasskey, webauthnSig, Kit, MODE_SINGLE, MODE_BATCH, MODE_DELEGATE, MODE_TRY_SINGLE, packSingle, packBatch, test, assert, reverts, results, abi, ethers };
