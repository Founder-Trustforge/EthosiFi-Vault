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
const CONFIRMATIONS = 2;  // avoid reorg noise

Deno.serve(async (req) => {
  if (req.headers.get("x-cron-secret") !== Deno.env.get("CRON_SECRET")) {
    return new Response("forbidden", { status: 403 });
  }
  const sb = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  const provider = new ethers.JsonRpcProvider(Deno.env.get("RPC_URL")!);
  const timelock = new ethers.Contract(Deno.env.get("TIMELOCK_ADDRESS")!, ABI, provider);

  const head = (await provider.getBlockNumber()) - CONFIRMATIONS;
  const { data: cur } = await sb.from("notify_cursor").select("last_block").eq("id", 1).maybeSingle();
  const from = cur ? Number(cur.last_block) + 1 : Number(Deno.env.get("START_BLOCK") ?? head);
  if (from > head) return Response.json({ ok: true, note: "up to date" });
  const to = Math.min(head, from + MAX_RANGE - 1);

  const logs = await timelock.queryFilter(timelock.filters.BiometricConfirmationRequested(), from, to);
  let sent = 0;

  for (const l of logs) {
    const { account, txHash, expiresAt } = (l as ethers.EventLog).args;
    const acct = String(account).toLowerCase();
    // Only verified numbers whose 72h "cool-off" has passed (a freshly added attacker number is inert).
    const { data: phones } = await sb.from("notify_phones").select("phone_e164")
      .eq("account", acct).eq("verified", true).lte("active_after", new Date().toISOString());

    const link = `${Deno.env.get("CONFIRM_BASE_URL")}?acct=${account}&tx=${txHash}`;
    const hours = Math.max(0, Math.round((Number(expiresAt) - Date.now() / 1000) / 3600));
    // Deliberately no amount/recipient/token in the text: those fields are caller-controlled
    // on-chain. The confirm page re-reads them from the chain and shows them in plain English.
    const body =
      `EthosiFi: a transfer from your Vault is waiting for your fingerprint. ` +
      `Review & confirm within ${hours}h or it is cancelled: ${link}\n` +
      `Didn't start this? Do nothing - it will expire. Never share codes.`;

    for (const p of phones ?? []) {
      const { error: dup } = await sb.from("notify_sent").insert({ tx_hash: txHash, phone_e164: p.phone_e164 });
      if (dup) continue; // already notified (unique key) — idempotent across retries
      const sid = await sendSms(p.phone_e164, body);
      if (!sid) { // send failed: free the slot so the next run retries
        await sb.from("notify_sent").delete().eq("tx_hash", txHash).eq("phone_e164", p.phone_e164);
        continue;
      }
      await sb.from("notify_sent").update({ twilio_sid: sid }).eq("tx_hash", txHash).eq("phone_e164", p.phone_e164);
      sent++;
    }
  }

  await sb.from("notify_cursor").upsert({ id: 1, last_block: to });
  return Response.json({ ok: true, from, to, events: logs.length, sent });
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
