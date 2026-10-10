// ethosifi.xyz hub: drop-in widget. Reads the cached briefing written by the market-intel function.
// <div id="market-intel"></div>   (anon key is fine: table is public-read, write is service-role only)
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const sb = createClient(window.SUPABASE_URL, window.SUPABASE_ANON_KEY);
const esc = (t) => String(t).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function render() {
  const { data } = await sb.from("market_intel").select("*").eq("id", 1).maybeSingle();
  if (!data) return;
  const px = data.prices.map((p) =>
    `<li>${esc(p.id)}: $${Number(p.usd).toLocaleString()} <small>${p.change24h == null ? "" : p.change24h.toFixed(2) + "%"}</small></li>`).join("");
  const sc = data.scams.map((s) =>
    `<li><b>${esc(s.name)}</b> (${esc(s.date)}) - $${Number(s.usd_lost || 0).toLocaleString()} lost${s.technique ? " via " + esc(s.technique) : ""}</li>`).join("");
  document.getElementById("market-intel").innerHTML =
    `<p>${esc(data.summary)}</p><h4>Prices</h4><ul>${px}</ul><h4>Latest exploits</h4><ul>${sc}</ul>` +
    `<small>Updated ${new Date(data.updated_at).toLocaleTimeString()} - not financial advice</small>`;
}
render(); setInterval(render, 60_000);
