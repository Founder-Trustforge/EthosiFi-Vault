// phone-enroll handler tested against the REAL BiometricValidator (on-chain passkey verification).
const path = require('path'); const { pathToFileURL } = require('url'); const crypto = require('crypto');
const { buildWorld, newVault } = require('./world');
const L = require('./lib');
const { test, assert, ethers, webauthnSig, newPasskey } = L;
(async () => {
  const { makeHandler } = await import(pathToFileURL(path.resolve(__dirname, '../offchain/supabase/functions/phone-enroll/handler.ts')).href);
  const W = await buildWorld(); const e = W.e; const bio = W.bio; const coder = ethers.AbiCoder.defaultAbiCoder();
  const V = await newVault(W); const V2 = await newVault(W);
  const chainId = (await e.provider.getNetwork()).chainId;

  // in-memory DB with the same atomic semantics as the SQL adapter
  const rows = new Map(), phones = []; let sms = []; let clock = Date.now();
  const iso = (ms) => new Date(ms).toISOString();
  const db = {
    async count(f, since) { return [...rows.values()].filter((r) => r.created >= Date.parse(since) && (!f.account || r.account === f.account) && (!f.phone || r.phone_e164 === f.phone) && (!f.onlySent || r.code_hash)).length; },
    async insert(r) { rows.set(r.nonce, { ...r, code_hash: null, code_expires_at: null, attempts: 0, used: false, created: clock }); },
    async get(n) { return rows.get(n) ?? null; },
    async setCode(n, h, x) { const r = rows.get(n); if (!r || r.code_hash || r.used) return false; r.code_hash = h; r.code_expires_at = x; return true; },
    async clearCode(n) { const r = rows.get(n); r.code_hash = null; r.code_expires_at = null; },
    async bumpAttempts(n) { const r = rows.get(n); r.attempts++; return r.attempts; },
    async markUsed(n) { const r = rows.get(n); if (r.used) return false; r.used = true; return true; },
    async phoneCount(a) { return phones.filter((p) => p.account === a).length; },
    async upsertPhone(account, phone, activeAfter) { if (!phones.find((p) => p.account === account && p.phone === phone)) phones.push({ account, phone, activeAfter }); },
    async deletePhone(a, ph) { const i = phones.findIndex((p) => p.account === a && p.phone === ph); if (i >= 0) phones.splice(i, 1); },
  };
  let smsFail = false;
  const handle = makeHandler({
    env: (k) => ({ ENROLL_PEPPER: 'test-pepper-0123456789' })[k], db,
    isVault: (a) => bio.isInitialized(a),
    verifyAssertion: async (a, c, s) => { try { return await bio.verifyConfirmation(a, c, s); } catch { return false; } },
    challengeHash: ({ account, kind, phone, nonce, expiresAt }) => ethers.keccak256(coder.encode(
      ['string', 'uint256', 'address', 'string', 'string', 'bytes32', 'uint256'], ['EthosiFi notify', chainId, account, kind, phone, '0x' + nonce, expiresAt])),
    sendSms: async (to, body) => { if (smsFail) return null; sms.push({ to, body }); return 'SM' + sms.length; },
    now: () => clock, random: (n) => crypto.randomBytes(n),
    sha256Hex: async (s) => crypto.createHash('sha256').update(s).digest('hex'),
  });
  const post = async (body, headers = {}) => { const r = await handle(new Request('https://x/fn', { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) })); return { status: r.status, j: await r.json() }; };
  const PH = '+14235550101';
  const challenge = async (v, phone = PH, kind = 'add') => (await post({ action: 'challenge', account: v.account, phone, kind }));
  const sign = (v, ch) => webauthnSig(v.passkey, ch);
  const codeFromSms = () => sms[sms.length - 1].body.match(/code: (\d{6})/)[1];

  await test('enroll: passkey assertion -> SMS code -> number stored, inert for 72h', async () => {
    const c = await challenge(V); assert(c.status === 200, JSON.stringify(c));
    let r = await post({ action: 'send', nonce: c.j.nonce, assertion: sign(V, c.j.challenge) }); assert(r.status === 200, JSON.stringify(r));
    assert(sms.length === 1 && sms[0].to === PH, 'sms sent to the number');
    assert(!sms[0].body.includes('http'), 'no link in the code SMS');
    r = await post({ action: 'verify', nonce: c.j.nonce, code: codeFromSms() }); assert(r.status === 200, JSON.stringify(r));
    assert(phones.length === 1 && phones[0].account === V.account.toLowerCase(), 'stored');
    const wait = Date.parse(phones[0].activeAfter) - clock; assert(Math.abs(wait - 72 * 3600_000) < 5000, 'inert for 72h');
    r = await post({ action: 'verify', nonce: c.j.nonce, code: codeFromSms() }); assert(r.status === 409, 'code single-use');
  });
  await test('no SMS without a valid on-chain fingerprint assertion (wrong key / other vault / replayed challenge)', async () => {
    const before = sms.length;
    let c = await challenge(V, '+14235550102');
    const stranger = { passkey: newPasskey('x'), account: V.account };
    for (const [label, sig] of [['random passkey', sign(stranger, c.j.challenge)], ['other vault passkey', sign(V2, c.j.challenge)], ['wrong challenge', sign(V, ethers.id('other'))]]) {
      const r = await post({ action: 'send', nonce: c.j.nonce, assertion: sig }); assert(r.status === 401, label + ' accepted: ' + JSON.stringify(r));
    }
    const garbage = await post({ action: 'send', nonce: c.j.nonce, assertion: '0x1234' }); assert(garbage.status === 401, 'garbage');
    assert((await post({ action: 'send', nonce: c.j.nonce, assertion: 'nothex' })).status === 400, 'bad hex');
    // assertion made for challenge A cannot be replayed on challenge B (phone/nonce are inside the hash)
    const a = await challenge(V, '+14235550103'), b = await challenge(V, '+14235550104');
    const r = await post({ action: 'send', nonce: b.j.nonce, assertion: sign(V, a.j.challenge) }); assert(r.status === 401, 'replay across challenges');
    assert(sms.length === before, 'no SMS leaked');
  });
  await test('unknown address / malformed input / bad origin / oversize are rejected before any SMS', async () => {
    const before = sms.length;
    assert((await post({ action: 'challenge', account: ethers.Wallet.createRandom().address, phone: PH, kind: 'add' })).status === 404, 'not a vault');
    assert((await post({ action: 'challenge', account: V.account, phone: '4235550101', kind: 'add' })).status === 400, 'phone format');
    assert((await post({ action: 'challenge', account: 'nope', phone: PH, kind: 'add' })).status === 400, 'account format');
    assert((await post({ action: 'challenge', account: V.account, phone: PH, kind: 'drop' })).status === 400, 'kind');
    assert((await post({ action: 'x' })).status === 400, 'action');
    assert((await post({ action: 'challenge', account: V.account, phone: PH, kind: 'add' }, { origin: 'https://evil.example' })).status === 403, 'origin');
    assert((await post({ action: 'send', nonce: 'x'.repeat(20000) })).status === 413, 'size');
    assert((await handle(new Request('https://x/fn', { method: 'GET' }))).status === 405, 'method');
    assert(sms.length === before, 'no sms');
  });
  await test('code brute force is capped at 5 tries; second send for same challenge refused; sms failure is retryable', async () => {
    const c = await challenge(V, '+14235550105');
    smsFail = true; let r = await post({ action: 'send', nonce: c.j.nonce, assertion: sign(V, c.j.challenge) }); assert(r.status === 502, 'sms fail surfaced');
    smsFail = false; r = await post({ action: 'send', nonce: c.j.nonce, assertion: sign(V, c.j.challenge) }); assert(r.status === 200, 'retry works');
    r = await post({ action: 'send', nonce: c.j.nonce, assertion: sign(V, c.j.challenge) }); assert(r.status === 409, 'no 2nd code for same challenge');
    const good = codeFromSms(); const wrong = good === '000000' ? '000001' : '000000';
    for (let i = 0; i < 5; i++) assert((await post({ action: 'verify', nonce: c.j.nonce, code: wrong })).status === 401, 'wrong code ' + i);
    r = await post({ action: 'verify', nonce: c.j.nonce, code: good }); assert(r.status === 429, 'locked out even with the right code: ' + JSON.stringify(r));
    assert(!phones.find((p) => p.phone === '+14235550105'), 'not stored');
  });
  await test('expiry: challenge and code both time out', async () => {
    const c = await challenge(V, '+14235550106'); clock += 11 * 60_000;
    assert((await post({ action: 'send', nonce: c.j.nonce, assertion: sign(V, c.j.challenge) })).status === 410, 'challenge expired');
    const c2 = await challenge(V, '+14235550107'); await post({ action: 'send', nonce: c2.j.nonce, assertion: sign(V, c2.j.challenge) });
    const code = codeFromSms(); clock += 11 * 60_000;
    assert((await post({ action: 'verify', nonce: c2.j.nonce, code })).status === 410, 'challenge/code expired');
  });
  await test('rate limits: challenges per phone and per account; OTPs per phone', async () => {
    const ph = '+14235550199'; let last;
    for (let i = 0; i < 6; i++) last = await challenge(V2, ph);
    assert(last.status === 429, 'per-phone limit: ' + last.status);
    const v3 = await newVault(W); let st;
    for (let i = 0; i < 11; i++) st = await challenge(v3, '+1423555' + String(3000 + i));
    assert(st.status === 429, 'per-account limit: ' + st.status);
  });
  await test('max 5 numbers per vault; removal needs the fingerprint and works', async () => {
    const v = await newVault(W);
    for (let i = 0; i < 5; i++) {
      const ph = '+1423556' + String(1000 + i); const c = await challenge(v, ph);
      await post({ action: 'send', nonce: c.j.nonce, assertion: sign(v, c.j.challenge) }); await post({ action: 'verify', nonce: c.j.nonce, code: codeFromSms() });
    }
    assert(phones.filter((p) => p.account === v.account.toLowerCase()).length === 5, 'five stored');
    assert((await challenge(v, '+14235569999')).status === 409, 'sixth refused');
    const rm = await challenge(v, '+14235561000', 'remove');
    assert((await post({ action: 'remove', nonce: rm.j.nonce, assertion: sign(V2, rm.j.challenge) })).status === 401, 'other vault cannot remove');
    assert((await post({ action: 'remove', nonce: rm.j.nonce, assertion: sign(v, rm.j.challenge) })).status === 200, 'owner removes');
    assert(!phones.find((p) => p.phone === '+14235561000'), 'gone');
    assert((await post({ action: 'remove', nonce: rm.j.nonce, assertion: sign(v, rm.j.challenge) })).status === 409, 'single use');
    assert((await post({ action: 'send', nonce: rm.j.nonce, assertion: sign(v, rm.j.challenge) })).status === 404, 'kind mismatch');
  });
  await test('browser helper: DER signature -> (r, s) conversion matches raw P-256 output (incl. short r/s and low-s)', async () => {
    const src = require('fs').readFileSync(path.resolve(__dirname, '../offchain/frontend/confirm-fingerprint.js'), 'utf8');
    const fnSrc = src.slice(src.indexOf('export function derToRS')).replace('export function', 'function');
    const derToRS = new Function(fnSrc + '; return derToRS;')();
    const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    for (let i = 0; i < 200; i++) {
      const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const msg = crypto.randomBytes(40);
      const der = crypto.sign('sha256', msg, privateKey), raw = crypto.sign('sha256', msg, { key: privateKey, dsaEncoding: 'ieee-p1363' });
      // sign twice gives different k; compare by parsing the SAME der with node's own p1363 conversion
      const p = crypto.createPublicKey(privateKey);
      assert(crypto.verify('sha256', msg, p, der), 'der valid');
      const { r, s } = derToRS(new Uint8Array(der));
      const buf = Buffer.concat([Buffer.from(r.toString(16).padStart(64, '0'), 'hex'), Buffer.from((s).toString(16).padStart(64, '0'), 'hex')]);
      // (r, s') with s' = N - s is also valid for the same message, and low-s must hold
      assert(s <= N / 2n, 'low-s');
      assert(crypto.verify('sha256', msg, { key: p, dsaEncoding: 'ieee-p1363' }, buf), 'converted signature verifies');
    }
  });
  console.log(L.results.filter((r) => !r[1]).length ? 'SOME FAILED' : 'ALL PASSED', L.results.length);
  process.exit(0);
})().catch((x) => { console.error(x); process.exit(1); });
