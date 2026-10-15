// Vault frontend (ethosifi.com): add / remove an alert phone number for a vault.
// Every step is authenticated by the owner's FINGERPRINT (passkey assertion verified on-chain by the server)
// plus an SMS one-time code. A new number only starts receiving alerts after 72 hours.
import { signChallenge } from "./confirm-fingerprint.js";

const FN = "https://<project-ref>.supabase.co/functions/v1/phone-enroll"; // set at build time

async function call(body) {
  const r = await fetch(FN, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.ok === false) throw new Error(j.error || `request failed (${r.status})`);
  return j;
}

/** Step 1+2: fingerprint -> SMS code is sent. Returns { nonce } to pass to verifyPhone(). */
export async function startAddPhone({ account, phone, credentialIdBytes32, credentialIdRaw }) {
  const c = await call({ action: "challenge", account, phone, kind: "add" });
  const assertion = await signChallenge({ challenge: c.challenge, credentialIdBytes32, credentialIdRaw });
  await call({ action: "send", nonce: c.nonce, assertion });
  return { nonce: c.nonce };
}

/** Step 3: type the code from the SMS. The number becomes active for alerts after `activeAfter`. */
export async function verifyPhone({ nonce, code }) {
  return call({ action: "verify", nonce, code });
}

export async function removePhone({ account, phone, credentialIdBytes32, credentialIdRaw }) {
  const c = await call({ action: "challenge", account, phone, kind: "remove" });
  const assertion = await signChallenge({ challenge: c.challenge, credentialIdBytes32, credentialIdRaw });
  return call({ action: "remove", nonce: c.nonce, assertion });
}
