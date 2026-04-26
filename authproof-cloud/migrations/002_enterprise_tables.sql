-- Migration 002: Enterprise feature tables
-- Run in Supabase Dashboard → SQL Editor

-- ─── White Label Configs ────────────────────────────────────────────────────

create table if not exists public.white_label_configs (
  id               uuid        primary key default gen_random_uuid(),
  account_id       uuid        not null references public.accounts(id) on delete cascade,
  company_name     text        not null,
  logo_url         text,
  logo_base64      text,
  primary_color    text        not null default '#1a56db',
  secondary_color  text        not null default '#1246b5',
  contact_email    text,
  contact_phone    text,
  address          text,
  footer_text      text,
  report_disclaimer text,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  unique (account_id)
);

alter table public.white_label_configs enable row level security;
create policy "Service role full access white_label_configs"
  on public.white_label_configs for all using (auth.role() = 'service_role');

-- ─── Legal Holds ────────────────────────────────────────────────────────────

create table if not exists public.legal_holds (
  id              uuid        primary key default gen_random_uuid(),
  account_id      uuid        not null references public.accounts(id) on delete cascade,
  organization_id uuid,
  name            text        not null,
  description     text,
  status          text        not null default 'active' check (status in ('active', 'released')),
  receipt_count   integer     not null default 0,
  created_by      text,
  expires_at      timestamptz,
  released_at     timestamptz,
  released_by     text,
  release_reason  text,
  created_at      timestamptz not null default now()
);

alter table public.legal_holds enable row level security;
create policy "Service role full access legal_holds"
  on public.legal_holds for all using (auth.role() = 'service_role');

create index if not exists legal_holds_account_id_idx on public.legal_holds (account_id, created_at desc);

-- ─── Legal Hold Items ────────────────────────────────────────────────────────

create table if not exists public.legal_hold_items (
  id            uuid        primary key default gen_random_uuid(),
  legal_hold_id uuid        not null references public.legal_holds(id) on delete cascade,
  item_type     text        not null default 'receipt',
  item_id       text,
  receipt_hash  text,
  added_by      text,
  added_at      timestamptz not null default now()
);

alter table public.legal_hold_items enable row level security;
create policy "Service role full access legal_hold_items"
  on public.legal_hold_items for all using (auth.role() = 'service_role');

create index if not exists legal_hold_items_hold_idx on public.legal_hold_items (legal_hold_id, added_at desc);

-- ─── Legal Hold Custody Log ─────────────────────────────────────────────────

create table if not exists public.legal_hold_custody_log (
  id            uuid        primary key default gen_random_uuid(),
  legal_hold_id uuid        not null references public.legal_holds(id) on delete cascade,
  action        text        not null,
  actor         text        not null,
  details       jsonb,
  occurred_at   timestamptz not null default now()
);

alter table public.legal_hold_custody_log enable row level security;
create policy "Service role full access legal_hold_custody_log"
  on public.legal_hold_custody_log for all using (auth.role() = 'service_role');

create index if not exists custody_log_hold_idx on public.legal_hold_custody_log (legal_hold_id, occurred_at asc);

-- ─── Team Members ───────────────────────────────────────────────────────────

create table if not exists public.team_members (
  id            uuid        primary key default gen_random_uuid(),
  account_id    uuid        not null references public.accounts(id) on delete cascade,
  email         text        not null,
  role          text        not null check (role in ('owner', 'admin', 'compliance_officer', 'viewer')),
  status        text        not null default 'pending' check (status in ('pending', 'accepted', 'removed')),
  invited_by    text,
  invited_at    timestamptz not null default now(),
  accepted_at   timestamptz,
  last_active_at timestamptz,
  jwt_secret    text
);

alter table public.team_members enable row level security;
create policy "Service role full access team_members"
  on public.team_members for all using (auth.role() = 'service_role');

create index if not exists team_members_account_idx on public.team_members (account_id);
create index if not exists team_members_email_idx   on public.team_members (email);

-- ─── Audit Access Log ───────────────────────────────────────────────────────

create table if not exists public.audit_access_log (
  id          uuid        primary key default gen_random_uuid(),
  account_id  uuid        not null references public.accounts(id) on delete cascade,
  member_id   uuid,
  actor       text        not null,
  action      text        not null,
  resource    text,
  resource_id text,
  ip          text,
  created_at  timestamptz not null default now()
);

alter table public.audit_access_log enable row level security;
create policy "Service role full access audit_access_log"
  on public.audit_access_log for all using (auth.role() = 'service_role');

create index if not exists audit_log_account_idx on public.audit_access_log (account_id, created_at desc);

-- ─── Organizations ───────────────────────────────────────────────────────────

create table if not exists public.organizations (
  id         uuid        primary key default gen_random_uuid(),
  account_id uuid        not null references public.accounts(id) on delete cascade,
  name       text        not null,
  slug       text        not null,
  created_at timestamptz not null default now(),
  unique (account_id, slug)
);

alter table public.organizations enable row level security;
create policy "Service role full access organizations"
  on public.organizations for all using (auth.role() = 'service_role');

create index if not exists organizations_account_idx on public.organizations (account_id);
create index if not exists organizations_slug_idx    on public.organizations (account_id, slug);

-- ─── Add enterprise columns to existing tables ───────────────────────────────

-- receipts: legal hold tracking
alter table public.receipts
  add column if not exists on_legal_hold boolean not null default false,
  add column if not exists legal_hold_id uuid;

-- verifications: legal hold tracking
alter table public.verifications
  add column if not exists on_legal_hold boolean not null default false;

-- tool_calls: legal hold tracking
alter table public.tool_calls
  add column if not exists on_legal_hold boolean not null default false;
