// phone-enroll — Supabase Edge Function (Deno). Public endpoint (deploy with --no-verify-jwt); every action is
// authenticated by a passkey assertion verified on-chain, plus an SMS one-time code. See handler.ts.
//
// Secrets: RPC_URL, BIOMETRIC_ADDRESS (isInitialized(account) recognises real vaults), CHAIN_ID,
//          ENROLL_PEPPER (>=16 random chars),
//          TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY (auto)
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { ethers } from "https://esm.sh/ethers@6.13.0";
import { makeHandler } from "./handler.ts";
import type { Db, EnrollRow } from "./handler.ts";

const env = (k: string) => Deno.env.get(k);
for (const k of ["RPC_URL", "BIOMETRIC_ADDRESS", "CHAIN_ID", "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM"]) {
  if (!env(k)) console.error(`phone-enroll: missing env ${k}`);
}
const sb = createClient(env("SUPABASE_URL")!, env("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
const provider = new ethers.JsonRpcProvider(env("RPC_URL")!, undefined, { staticNetwork: true });
const bio = new ethers.Contract(env("BIOMETRIC_ADDRESS") ?? ethers.ZeroAddress, [
  "function isInitialized(address) view returns (bool)",
  "function verifyConfirmation(address,bytes32,bytes) view returns (bool)",
], provider);
const coder = ethers.AbiCoder.defaultAbiCoder();

const db: Db = {
  async count(f, since) {
    let q = sb.from("notify_enroll").select("nonce", { count: "exact", head: true }).gte("created_at", since);
    if (f.account) q = q.eq("account", f.account);
    if (f.phone) q = q.eq("phone_e164", f.phone);
    if (f.onlySent) q = q.not("code_hash", "is", null);
    const { count, error } = await q; if (error) throw new Error(error.message); return count ?? 0;
  },
  async insert(row) { const { error } = await sb.from("notify_enroll").insert(row); if (error) throw new Error(error.message); },
  async get(nonce) {
    const { data, error } = await sb.from("notify_enroll").select("*").eq("nonce", nonce).maybeSingle();
    if (error) throw new Error(error.message); return (data as EnrollRow) ?? null;
  },
  async setCode(nonce, hash, exp) {
    const { data, error } = await sb.from("notify_enroll").update({ code_hash: hash, code_expires_at: exp })
      .eq("nonce", nonce).is("code_hash", null).eq("used", false).select("nonce");
    if (error) throw new Error(error.message); return (data?.length ?? 0) === 1;
  },
  async clearCode(nonce) { await sb.from("notify_enroll").update({ code_hash: null, code_expires_at: null }).eq("nonce", nonce); },
  async bumpAttempts(nonce) {
    const { data, error } = await sb.rpc("notify_enroll_attempt", { p_nonce: nonce });
    if (error) throw new Error(error.message); return Number(data);
  },
  async markUsed(nonce) {
    const { data, error } = await sb.from("notify_enroll").update({ used: true }).eq("nonce", nonce).eq("used", false).select("nonce");
    if (error) throw new Error(error.message); return (data?.length ?? 0) === 1;
  },
  async phoneCount(account) {
    const { count, error } = await sb.from("notify_phones").select("id", { count: "exact", head: true }).eq("account", account);
    if (error) throw new Error(error.message); return count ?? 0;
  },
  async upsertPhone(account, phone, activeAfter) {
    const { data } = await sb.from("notify_phones").select("id").eq("account", account).eq("phone_e164", phone).maybeSingle();
    const { error } = data
      ? await sb.from("notify_phones").update({ verified: true }).eq("id", data.id)   // never shortens an existing wait
      : await sb.from("notify_phones").insert({ account, phone_e164: phone, verified: true, active_after: activeAfter });
    if (error) throw new Error(error.message);
  },
  async deletePhone(account, phone) {
    const { error } = await sb.from("notify_phones").delete().eq("account", account).eq("phone_e164", phone);
    if (error) throw new Error(error.message);
  },
};

const handler = makeHandler({
  env, db,
  isVault: async (a) => await bio.isInitialized(a),
  verifyAssertion: async (a, c, s) => { try { return await bio.verifyConfirmation(a, c, s); } catch { return false; } },
  // MUST match offchain/frontend/enroll-phone.js (the client signs the challenge the server returns, but this pins its contents).
  challengeHash: ({ account, kind, phone, nonce, expiresAt }) => ethers.keccak256(coder.encode(
    ["string", "uint256", "address", "string", "string", "bytes32", "uint256"],
    ["EthosiFi notify", BigInt(env("CHAIN_ID")!), account, kind, phone, "0x" + nonce, expiresAt])),
  sendSms,
  now: () => Date.now(),
  random: (n) => crypto.getRandomValues(new Uint8Array(n)),
  sha256Hex: async (s) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))]
    .map((x) => x.toString(16).padStart(2, "0")).join(""),
});
Deno.serve(handler);

async function sendSms(to: string, body: string): Promise<string | null> {
  const sid = env("TWILIO_ACCOUNT_SID")!;
  const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
    method: "POST",
    headers: { Authorization: "Basic " + btoa(`${sid}:${env("TWILIO_AUTH_TOKEN")}`), "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ To: to, From: env("TWILIO_FROM")!, Body: body }),
  });
  if (!res.ok) { console.error("twilio", res.status); return null; }
  return (await res.json()).sid ?? null;
}
