// Vault frontend: the page the SMS links to (…/confirm?acct=0x..&tx=0x..).
// Reads the pending transfer FROM THE CHAIN (never from the URL/SMS), shows it, then asks the
// device for the enrolled fingerprint/passkey and relays the assertion to TimeLockValidator.
import { ethers } from "ethers"; // v6

const TL_ABI = [
  "function confirmationChallenge(address,bytes32) view returns (bytes32)",
  "function confirmAndRelease(address,bytes32,bytes)",
  "event BiometricConfirmationRequested(address indexed account, bytes32 indexed txHash, address token, uint256 amount, address recipient, uint256 expiresAt)",
];
const SIG_TYPE = "tuple(bytes authenticatorData, bytes clientDataJSON, uint256 challengeOffset, uint256[2] rs, bytes32 credentialId)";

export async function loadRequest(provider, timelockAddr, acct, txHash) {
  const tl = new ethers.Contract(timelockAddr, TL_ABI, provider);
  const [ev] = await tl.queryFilter(tl.filters.BiometricConfirmationRequested(acct, txHash), -50000);
  if (!ev) throw new Error("Transfer not found");
  const { token, amount, recipient, expiresAt } = ev.args;
  return { token, amount, recipient, expiresAt: Number(expiresAt) }; // render in plain English; show full recipient address
}

export async function confirmWithFingerprint({ signer, timelockAddr, acct, txHash, credentialIdBytes32, credentialIdRaw }) {
  const tl = new ethers.Contract(timelockAddr, TL_ABI, signer);
  const challenge = await tl.confirmationChallenge(acct, txHash); // bytes32 hex

  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: ethers.getBytes(challenge),
      rpId: "ethosifi.xyz",                       // MUST match the rpIdHash enrolled at signup
      allowCredentials: [{ type: "public-key", id: credentialIdRaw }],
      userVerification: "required",               // forces the fingerprint / biometric, not just a tap
    },
  });
  const r = cred.response;
  const clientDataJSON = new Uint8Array(r.clientDataJSON);
  const text = new TextDecoder().decode(clientDataJSON);
  const challengeOffset = text.indexOf('"challenge":"') + '"challenge":"'.length;
  const { r: rr, s } = derToRS(new Uint8Array(r.signature));

  const encoded = ethers.AbiCoder.defaultAbiCoder().encode([SIG_TYPE], [[
    new Uint8Array(r.authenticatorData), clientDataJSON, challengeOffset, [rr, s], credentialIdBytes32,
  ]]);
  const tx = await tl.confirmAndRelease(acct, txHash, encoded);
  return tx.wait();
}

// WebAuthn returns an ASN.1 DER ECDSA signature; the contract wants (r, s) with low-s.
function derToRS(der) {
  let o = 2; if (der[1] & 0x80) o += der[1] & 0x7f;
  const rl = der[o + 1]; const r = der.slice(o + 2, o + 2 + rl);
  o = o + 2 + rl; const sl = der[o + 1]; const s = der.slice(o + 2, o + 2 + sl);
  const N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
  const big = (b) => BigInt("0x" + [...b].map((x) => x.toString(16).padStart(2, "0")).join(""));
  let sv = big(s); if (sv > N / 2n) sv = N - sv;
  return { r: big(r), s: sv };
}
