// tx-notifier — Supabase Edge Function (Deno). Run every minute (pg_cron / scheduled invoke).
//
// Watches TimeLockValidator for BiometricConfirmationRequested and texts the vault
// owner a link to confirm the transfer with their enrolled fingerprint (WebAuthn).
//
// SECURITY MODEL: the SMS is only a *notification*. It carries no code and approves
// nothing. Release requires a WebAuthn assertion from a passkey enrolled on the vault,
// verified on-chain. A SIM-swapped / spoofed number can never release funds; at worst
// the owner isn't alerted and the transfer expires (fail-safe) after 48h.
//
// Secrets: RPC_URL, TIMELOCK_ADDRESS, CONFIRM_BASE_URL (e.g. https://ethosifi.com/confirm),
//          TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM, CRON_SECRET,
//          SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY (auto-provided), START_BLOCK (first run only)
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { ethers } from "https://esm.sh/ethers@6.13.0";

const ABI = [
  "event BiometricConfirmationRequested(address indexed account, bytes32 indexed txHash, address token, uint256 amount, address recipient, uint256 expiresAt)",
];
const MAX_RANGE = 2000;   // blocks per run
const CONFIRMATIONS = 6;  // avoid reorg noise
const OVERLAP = 12;       // blocks re-scanned every run
const MAX_SMS_PER_HOUR = 6;

function constEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

Deno.serve(async (req) => {
  const secret = Deno.env.get("CRON_SECRET");
  if (!secret || !constEq(req.headers.get("x-cron-secret") ?? "", secret)) {
    return new Response("forbidden", { status: 403 });
  }
  for (const k of ["RPC_URL", "TIMELOCK_ADDRESS", "CONFIRM_BASE_URL", "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM"]) {
    if (!Deno.env.get(k)) return new Response(`missing env ${k}`, { status: 500 });
  }
  const base = Deno.env.get("CONFIRM_BASE_URL")!;
  // The SMS link must point at the VAULT (ethosifi.com), never the hub (ethosifi.xyz) or anything else.
  if (!base.startsWith("https://ethosifi.com/")) return new Response("CONFIRM_BASE_URL must be on https://ethosifi.com/", { status: 500 });

  const sb = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  const provider = new ethers.JsonRpcProvider(Deno.env.get("RPC_URL")!, undefined, { staticNetwork: true });
  const timelock = new ethers.Contract(Deno.env.get("TIMELOCK_ADDRESS")!, ABI, provider);

  const head = (await provider.getBlockNumber()) - CONFIRMATIONS;
  const { data: cur, error: curErr } = await sb.from("notify_cursor").select("last_block").eq("id", 1).maybeSingle();
  if (curErr) throw new Error(`cursor read: ${curErr.message}`); // never guess a start block on a DB error
  const startEnv = Deno.env.get("START_BLOCK");
  if (!cur && !startEnv) return new Response("first run needs START_BLOCK", { status: 500 });
  // Re-scan a small overlap each run (reorg safety); notify_sent makes it idempotent.
  const from = cur ? Math.max(0, Number(cur.last_block) + 1 - OVERLAP) : Number(startEnv);
  if (from > head) return Response.json({ ok: true, note: "up to date" });
  const to = Math.min(head, from + MAX_RANGE - 1);

  const logs = await timelock.queryFilter(timelock.filters.BiometricConfirmationRequested(), from, to);
  let sent = 0;
  let firstFailedBlock: number | null = null;

  for (const l of logs) {
    const { account, txHash, expiresAt } = (l as ethers.EventLog).args;
    const secsLeft = Number(expiresAt) - Date.now() / 1000;
    if (secsLeft <= 0) continue; // already expired: nothing to confirm, don't text
    const acct = String(account).toLowerCase();

    const { data: phones, error: phErr } = await sb.from("notify_phones").select("phone_e164")
      .eq("account", acct).eq("verified", true).lte("active_after", new Date().toISOString());
    if (phErr) { firstFailedBlock ??= l.blockNumber; continue; }

    const link = `${base}?acct=${account}&tx=${txHash}`;
    const hours = Math.max(1, Math.floor(secsLeft / 3600));
    // Deliberately no amount/recipient/token in the text: those fields are caller-controlled
    // on-chain. The confirm page re-reads them from the chain and shows them in plain English.
    const body =
      `EthosiFi: a transfer from your Vault is waiting for your fingerprint. ` +
      `Review & confirm within ${hours}h or it is cancelled: ${link}\n` +
      `Didn't start this? Do nothing - it will expire. Never share codes.`;

    for (const p of phones ?? []) {
      // Cost / harassment cap: a stolen spending key can queue transfers, but never makes us text a number > MAX_SMS_PER_HOUR/h.
      const { count: recent, error: rateErr } = await sb.from("notify_sent").select("tx_hash", { count: "exact", head: true })
        .eq("phone_e164", p.phone_e164).gte("sent_at", new Date(Date.now() - 3_600_000).toISOString());
      if (rateErr) { firstFailedBlock ??= l.blockNumber; continue; }
      if ((recent ?? 0) >= MAX_SMS_PER_HOUR) { console.warn("rate-limited", p.phone_e164.slice(0, 5) + "…"); continue; }
      const { error: insErr } = await sb.from("notify_sent").insert({ tx_hash: txHash, phone_e164: p.phone_e164 });
      if (insErr) {
        if (insErr.code === "23505") continue; // genuine duplicate: already notified
        firstFailedBlock ??= l.blockNumber;      // any other DB error: retry next run
        continue;
      }
      let sid: string | null = null;
      try { sid = await sendSms(p.phone_e164, body); } catch (e) { console.error("sms", e); }
      if (!sid) { // failed: free the slot and keep the cursor behind this block so it retries
        await sb.from("notify_sent").delete().eq("tx_hash", txHash).eq("phone_e164", p.phone_e164);
        firstFailedBlock ??= l.blockNumber;
        continue;
      }
      await sb.from("notify_sent").update({ twilio_sid: sid }).eq("tx_hash", txHash).eq("phone_e164", p.phone_e164);
      sent++;
    }
  }

  const newCursor = firstFailedBlock !== null ? Math.max(from - 1, firstFailedBlock - 1) : to;
  const { error: upErr } = await sb.from("notify_cursor").upsert({ id: 1, last_block: newCursor });
  if (upErr) throw new Error(`cursor write: ${upErr.message}`);
  return Response.json({ ok: firstFailedBlock === null, from, to, cursor: newCursor, events: logs.length, sent });
});

async function sendSms(to: string, body: string): Promise<string | null> {
  const sid = Deno.env.get("TWILIO_ACCOUNT_SID")!;
  const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
    method: "POST",
    headers: {
      Authorization: "Basic " + btoa(`${sid}:${Deno.env.get("TWILIO_AUTH_TOKEN")}`),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ To: to, From: Deno.env.get("TWILIO_FROM")!, Body: body }),
  });
  if (!res.ok) { console.error("twilio", res.status, await res.text()); return null; }
  return (await res.json()).sid ?? null;
}
