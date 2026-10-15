-- Phone numbers the owner wants alerted. One row per number (multiple allowed).
create table if not exists public.notify_phones (
  id uuid primary key default gen_random_uuid(),
  account text not null,                 -- vault address, lowercase 0x...
  phone_e164 text not null,
  verified boolean not null default false,
  active_after timestamptz not null default now() + interval '72 hours', -- new numbers are inert for 72h
  created_at timestamptz not null default now(),
  unique (account, phone_e164)
);
alter table public.notify_phones enable row level security;   -- service role only; no public policies

create table if not exists public.notify_cursor (
  id int primary key default 1,
  last_block bigint not null,
  check (id = 1)
);
alter table public.notify_cursor enable row level security;

create table if not exists public.notify_sent (
  tx_hash text not null,                 -- pending-tx hash
  phone_e164 text not null,
  sent_at timestamptz not null default now(),
  twilio_sid text,
  primary key (tx_hash, phone_e164)
);
alter table public.notify_sent enable row level security;

-- Cached output of the market-intel agent (read by the hub frontend).
create table if not exists public.market_intel (
  id int primary key default 1,
  updated_at timestamptz not null default now(),
  prices jsonb not null default '[]',
  scams jsonb not null default '[]',
  summary text not null default '',
  check (id = 1)
);
alter table public.market_intel enable row level security;
create policy "public read market_intel" on public.market_intel for select using (true);

-- Phone enrollment (one row per challenge). Service role only. Proves BOTH vault ownership (passkey assertion
-- verified on-chain) and phone control (SMS one-time code) before a number is ever added.
create table if not exists public.notify_enroll (
  nonce text primary key,                 -- 32 random bytes, hex
  account text not null,
  phone_e164 text not null,
  kind text not null check (kind in ('add','remove')),
  challenge text not null,                -- 0x… bytes32 the passkey must sign
  expires_at timestamptz not null,
  code_hash text,                         -- sha256(nonce:code:pepper); set once, when the SMS is sent
  code_expires_at timestamptz,
  attempts int not null default 0,
  used boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists notify_enroll_account_idx on public.notify_enroll (account, created_at);
create index if not exists notify_enroll_phone_idx on public.notify_enroll (phone_e164, created_at);
alter table public.notify_enroll enable row level security;

create or replace function public.notify_enroll_attempt(p_nonce text) returns int
language sql security definer set search_path = public as $$
  update public.notify_enroll set attempts = attempts + 1 where nonce = p_nonce and not used returning attempts;
$$;
revoke all on function public.notify_enroll_attempt(text) from public, anon, authenticated;
