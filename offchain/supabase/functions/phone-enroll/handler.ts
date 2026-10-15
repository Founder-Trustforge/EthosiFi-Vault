// phone-enroll core logic. No network imports: everything external is injected, so it is unit-tested
// (integration-tests/suite_offchain.js) against the real BiometricValidator with a real passkey assertion.
//
// Adding a number needs THREE things, so a stolen spending key, a leaked API or a SIM-swap alone is not enough:
//   1. a passkey (fingerprint) assertion by the vault owner over a server-issued challenge, verified ON-CHAIN;
//   2. control of the phone (SMS one-time code);
//   3. a 72h wait (notify_phones.active_after) before the number is used for alerts.
// The SMS code is only ever sent AFTER step 1, so this endpoint can't be used to text arbitrary people on demand.

export interface EnrollRow {
  nonce: string; account: string; phone_e164: string; kind: "add" | "remove"; challenge: string;
  expires_at: string; code_hash: string | null; code_expires_at: string | null; attempts: number; used: boolean;
}
export interface Db {
  count(filter: { account?: string; phone?: string; onlySent?: boolean }, sinceIso: string): Promise<number>;
  insert(row: Omit<EnrollRow, "code_hash" | "code_expires_at" | "attempts" | "used">): Promise<void>;
  get(nonce: string): Promise<EnrollRow | null>;
  setCode(nonce: string, hash: string, expiresIso: string): Promise<boolean>; // only if code_hash is null & !used
  clearCode(nonce: string): Promise<void>;
  bumpAttempts(nonce: string): Promise<number>;
  markUsed(nonce: string): Promise<boolean>; // atomic: true only for the first caller
  phoneCount(account: string): Promise<number>;
  upsertPhone(account: string, phone: string, activeAfterIso: string): Promise<void>;
  deletePhone(account: string, phone: string): Promise<void>;
}
export interface Deps {
  env(k: string): string | undefined;
  db: Db;
  isVault(account: string): Promise<boolean>;
  verifyAssertion(account: string, challenge: string, assertionHex: string): Promise<boolean>;
  challengeHash(a: { account: string; kind: string; phone: string; nonce: string; expiresAt: number }): string;
  sendSms(to: string, body: string): Promise<string | null>;
  now(): number;                       // ms
  random(n: number): Uint8Array;
  sha256Hex(s: string): Promise<string>;
}

const ORIGIN = "https://ethosifi.com";
const ADDR = /^0x[0-9a-fA-F]{40}$/;
const E164 = /^\+[1-9]\d{7,14}$/;
const HEX = /^0x([0-9a-fA-F]{2})+$/;
const NONCE = /^[0-9a-f]{64}$/;
const CHALLENGE_TTL_S = 600, CODE_TTL_S = 600, MAX_ATTEMPTS = 5, MAX_PHONES = 5, ACTIVATION_DELAY_H = 72;
const DAY_MS = 86_400_000;

const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "access-control-allow-origin": ORIGIN, vary: "origin", "cache-control": "no-store" },
  });
const bad = (msg: string, status = 400) => json(status, { ok: false, error: msg });

function constEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

export function makeHandler(d: Deps) {
  return async (req: Request): Promise<Response> => {
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: {
        "access-control-allow-origin": ORIGIN, "access-control-allow-methods": "POST, OPTIONS",
        "access-control-allow-headers": "content-type", "access-control-max-age": "600", vary: "origin" } });
    }
    if (req.method !== "POST") return bad("method", 405);
    // Browsers only: reject other origins outright (CORS alone doesn't stop non-browser callers; limits below do).
    const origin = req.headers.get("origin");
    if (origin !== null && origin !== ORIGIN) return bad("origin", 403);
    const text = await req.text();
    if (text.length > 16_384) return bad("too large", 413);
    let b: any;
    try { b = JSON.parse(text); } catch { return bad("json"); }
    if (b === null || typeof b !== "object") return bad("json");
    const pepper = d.env("ENROLL_PEPPER");
    if (!pepper || pepper.length < 16) return bad("not configured", 500);

    const nowMs = d.now();
    const iso = (ms: number) => new Date(ms).toISOString();

    switch (b.action) {
      case "challenge": {
        const account = String(b.account ?? "").toLowerCase(), phone = String(b.phone ?? ""), kind = String(b.kind ?? "");
        if (!ADDR.test(account) || !E164.test(phone) || (kind !== "add" && kind !== "remove")) return bad("invalid input");
        if (!(await d.isVault(account))) return bad("unknown vault", 404);
        const since = iso(nowMs - DAY_MS);
        if ((await d.db.count({ account }, since)) >= 10 || (await d.db.count({ phone }, since)) >= 5) return bad("rate limited", 429);
        if (kind === "add" && (await d.db.phoneCount(account)) >= MAX_PHONES) return bad("too many numbers", 409);
        const nonce = hex(d.random(32));
        const expiresAt = Math.floor(nowMs / 1000) + CHALLENGE_TTL_S;
        const challenge = d.challengeHash({ account, kind, phone, nonce, expiresAt });
        await d.db.insert({ nonce, account, phone_e164: phone, kind, challenge, expires_at: iso(expiresAt * 1000) });
        return json(200, { ok: true, nonce, expiresAt, challenge });
      }

      case "send": { // step 2 of "add": passkey assertion -> SMS code
        const row = await load(b.nonce, "add");
        if (row instanceof Response) return row;
        if (typeof b.assertion !== "string" || !HEX.test(b.assertion)) return bad("assertion");
        if (!(await d.verifyAssertion(row.account, row.challenge, b.assertion))) return bad("fingerprint not accepted", 401);
        if ((await d.db.count({ phone: row.phone_e164, onlySent: true }, iso(nowMs - DAY_MS))) >= 3) return bad("rate limited", 429);
        const code = String(sixDigits(d)).padStart(6, "0");
        const hash = await d.sha256Hex(`${row.nonce}:${code}:${pepper}`);
        if (!(await d.db.setCode(row.nonce, hash, iso(nowMs + CODE_TTL_S * 1000)))) return bad("code already sent", 409);
        const sid = await d.sendSms(row.phone_e164,
          `EthosiFi verification code: ${code}. Enter it only on ethosifi.com. We will never ask you to share it. Expires in 10 min.`)
          .catch(() => null);
        if (!sid) { await d.db.clearCode(row.nonce); return bad("sms failed", 502); }
        return json(200, { ok: true });
      }

      case "verify": { // step 3 of "add": SMS code -> number stored (inert for 72h)
        const row = await load(b.nonce, "add");
        if (row instanceof Response) return row;
        if (typeof b.code !== "string" || !/^\d{6}$/.test(b.code)) return bad("code");
        if (!row.code_hash || !row.code_expires_at || Date.parse(row.code_expires_at) <= nowMs) return bad("no active code", 409);
        const attempts = await d.db.bumpAttempts(row.nonce);
        if (attempts > MAX_ATTEMPTS) return bad("too many attempts", 429);
        const got = await d.sha256Hex(`${row.nonce}:${b.code}:${pepper}`);
        if (!constEq(got, row.code_hash)) return bad("wrong code", 401);
        if (!(await d.db.markUsed(row.nonce))) return bad("already used", 409);
        if ((await d.db.phoneCount(row.account)) >= MAX_PHONES) return bad("too many numbers", 409);
        const activeAfter = iso(nowMs + ACTIVATION_DELAY_H * 3_600_000);
        await d.db.upsertPhone(row.account, row.phone_e164, activeAfter);
        return json(200, { ok: true, activeAfter });
      }

      case "remove": { // passkey assertion alone is enough to REMOVE a number
        const row = await load(b.nonce, "remove");
        if (row instanceof Response) return row;
        if (typeof b.assertion !== "string" || !HEX.test(b.assertion)) return bad("assertion");
        if (!(await d.verifyAssertion(row.account, row.challenge, b.assertion))) return bad("fingerprint not accepted", 401);
        if (!(await d.db.markUsed(row.nonce))) return bad("already used", 409);
        await d.db.deletePhone(row.account, row.phone_e164);
        return json(200, { ok: true });
      }
      default:
        return bad("unknown action");
    }

    async function load(nonce: unknown, kind: "add" | "remove"): Promise<EnrollRow | Response> {
      if (typeof nonce !== "string" || !NONCE.test(nonce)) return bad("nonce");
      const row = await d.db.get(nonce);
      if (!row || row.kind !== kind) return bad("unknown challenge", 404);
      if (row.used) return bad("already used", 409);
      if (Date.parse(row.expires_at) <= nowMs) return bad("challenge expired", 410);
      return row;
    }
  };
}

/** Uniform 6-digit number (rejection sampling on 32 random bits: no modulo bias). */
function sixDigits(d: Deps): number {
  const lim = 4_294_000_000; // largest multiple of 1e6 that fits in 32 bits
  for (let i = 0; i < 64; i++) {
    const r = d.random(4);
    const v = ((r[0] << 24) | (r[1] << 16) | (r[2] << 8) | r[3]) >>> 0;
    if (v < lim) return v % 1_000_000;
  }
  throw new Error("rng");
}
