-- Delegation Receipt Protocol — Supabase Schema
-- Run this in the Supabase SQL editor (Dashboard → SQL Editor → New query)

-- ─── Table ────────────────────────────────────────────────────────────────────

create table if not exists public.receipts (
  id                    bigserial primary key,
  hash                  text        not null unique,
  delegation_id         text        not null,
  scope                 text        not null,
  boundaries            text        not null,
  time_window_start     timestamptz not null,
  time_window_end       timestamptz not null,
  operator_instructions text        not null,
  instructions_hash     text        not null,
  signer_public_key     jsonb       not null,   -- { kty, crv, x, y }
  signature             text        not null,
  issued_at             timestamptz not null default now(),
  revoked               boolean     not null default false,
  revoked_at            timestamptz
);

-- ─── Indexes ──────────────────────────────────────────────────────────────────

create index if not exists receipts_hash_idx          on public.receipts (hash);
create index if not exists receipts_delegation_id_idx on public.receipts (delegation_id);
create index if not exists receipts_issued_at_idx     on public.receipts (issued_at desc);
create index if not exists receipts_revoked_idx       on public.receipts (revoked) where revoked = true;

-- ─── Row Level Security ───────────────────────────────────────────────────────

alter table public.receipts enable row level security;

-- Anyone can read receipts (needed for public verification)
create policy "Public read receipts"
  on public.receipts for select
  using (true);

-- Anyone can insert a new receipt (issuing is open — rate-limit via edge function if needed)
create policy "Public insert receipts"
  on public.receipts for insert
  with check (true);

-- Only the service role (edge functions) can update (revoke)
-- The revoke edge function runs with the service role key, so this blocks direct client updates
create policy "Service role update receipts"
  on public.receipts for update
  using (auth.role() = 'service_role');

-- ─── Helper view ─────────────────────────────────────────────────────────────

create or replace view public.active_receipts as
  select * from public.receipts where revoked = false;
