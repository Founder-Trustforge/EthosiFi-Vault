# EthosiFi off-chain pieces

## Flow
1. Standard-key tx is over the 24h budget / high value -> vault calls `TimeLockValidator.initiateDelayedTx` -> event `BiometricConfirmationRequested`.
2. `tx-notifier` (cron, every minute) texts the owner's verified numbers a link to `ethosifi.com/confirm?acct=..&tx=..`.
3. Confirm page reads the transfer from chain, user scans fingerprint (WebAuthn, enrolled passkey) -> `confirmAndRelease` verifies it on-chain -> funds move.
4. No valid fingerprint within 48h -> `confirmAndRelease` reverts "Expired"; anyone may call `expireTx` to mark it cancelled.

## Deploy
supabase db push   # migration in supabase/migrations
supabase functions deploy tx-notifier --no-verify-jwt
supabase functions deploy market-intel --no-verify-jwt
supabase secrets set CRON_SECRET=... RPC_URL=... TIMELOCK_ADDRESS=... CONFIRM_BASE_URL=https://ethosifi.com/confirm \
  TWILIO_ACCOUNT_SID=... TWILIO_AUTH_TOKEN=... TWILIO_FROM=+1... ANTHROPIC_API_KEY=... START_BLOCK=<deploy block>
-- cron (SQL editor, pg_cron + pg_net):
select cron.schedule('tx-notifier','* * * * *', $$select net.http_post('https://<ref>.supabase.co/functions/v1/tx-notifier', '{}'::jsonb, headers:='{"x-cron-secret":"<CRON_SECRET>"}'::jsonb)$$);
select cron.schedule('market-intel','*/5 * * * *', $$select net.http_post('https://<ref>.supabase.co/functions/v1/market-intel', '{}'::jsonb, headers:='{"x-cron-secret":"<CRON_SECRET>"}'::jsonb)$$);

## Not built yet
Phone-number enrollment endpoint (must require a fingerprint/passkey assertion from the vault + OTP to the number;
new numbers sit inert 72h via notify_phones.active_after). Until then insert rows manually (service role).
