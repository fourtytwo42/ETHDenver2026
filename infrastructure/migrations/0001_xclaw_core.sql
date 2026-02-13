-- X-Claw canonical MVP migration baseline (Slice 02 contract freeze)

create extension if not exists pgcrypto;

create type runtime_platform as enum ('windows', 'linux', 'macos');
create type public_status as enum ('active', 'offline', 'degraded', 'paused', 'deactivated');
create type custody_type as enum ('agent_local');
create type policy_mode as enum ('mock', 'real');
create type policy_approval_mode as enum ('per_trade', 'auto');

create type trade_status as enum (
  'proposed',
  'approval_pending',
  'approved',
  'rejected',
  'executing',
  'verifying',
  'filled',
  'failed',
  'expired',
  'verification_timeout'
);

create type agent_event_type as enum (
  'heartbeat',
  'trade_proposed',
  'trade_approval_pending',
  'trade_approved',
  'trade_rejected',
  'trade_executing',
  'trade_verifying',
  'trade_filled',
  'trade_failed',
  'trade_expired',
  'trade_verification_timeout',
  'policy_changed'
);

create type performance_window as enum ('24h', '7d', '30d', 'all');
create type management_token_status as enum ('active', 'rotated', 'revoked');
create type stepup_issued_for as enum ('withdraw', 'approval_scope_change', 'sensitive_action');
create type management_action_status as enum ('accepted', 'rejected', 'failed');
create type approval_scope as enum ('trade', 'pair', 'global');
create type approval_status as enum ('active', 'revoked', 'expired', 'consumed');
create type offdex_settlement_status as enum (
  'proposed',
  'accepted',
  'maker_funded',
  'taker_funded',
  'ready_to_settle',
  'settling',
  'settled',
  'cancelled',
  'expired',
  'failed'
);

create table if not exists agents (
  agent_id text primary key,
  agent_name varchar(32) unique not null,
  description varchar(280),
  owner_label varchar(64),
  runtime_platform runtime_platform not null default 'linux',
  openclaw_runtime_id varchar(128),
  openclaw_metadata jsonb not null default '{}'::jsonb,
  public_status public_status not null default 'offline',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists agent_wallets (
  wallet_id text primary key,
  agent_id text not null references agents(agent_id),
  chain_key varchar(64) not null,
  address varchar(128) not null,
  custody custody_type not null default 'agent_local',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (agent_id, chain_key)
);

create table if not exists agent_policy_snapshots (
  snapshot_id text primary key,
  agent_id text not null references agents(agent_id),
  mode policy_mode not null,
  approval_mode policy_approval_mode not null,
  max_trade_usd numeric,
  max_daily_usd numeric,
  allowed_tokens jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists trades (
  trade_id text primary key,
  agent_id text not null references agents(agent_id),
  chain_key varchar(64) not null,
  is_mock boolean not null,
  status trade_status not null,
  token_in varchar(128) not null,
  token_out varchar(128) not null,
  pair varchar(128) not null,
  amount_in numeric,
  amount_out numeric,
  price_impact_bps int,
  slippage_bps int,
  reason varchar(140),
  reason_code varchar(64),
  reason_message text,
  tx_hash varchar(128),
  mock_receipt_id varchar(128),
  error_message text,
  source_trade_id text,
  executed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint trade_execution_id_check
    check ((tx_hash is not null) or (mock_receipt_id is not null) or status in ('proposed', 'approval_pending', 'approved', 'rejected', 'expired'))
);

create table if not exists agent_events (
  event_id text primary key,
  agent_id text not null references agents(agent_id),
  trade_id text references trades(trade_id),
  event_type agent_event_type not null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists performance_snapshots (
  snapshot_id text primary key,
  agent_id text not null references agents(agent_id),
  "window" performance_window not null,
  pnl_usd numeric,
  return_pct numeric,
  volume_usd numeric,
  win_rate_pct numeric,
  trades_count int not null default 0,
  followers_count int not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists copy_subscriptions (
  subscription_id text primary key,
  leader_agent_id text not null references agents(agent_id),
  follower_agent_id text not null references agents(agent_id),
  enabled boolean not null default true,
  scale_bps int not null default 10000,
  max_trade_usd numeric,
  allowed_tokens jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists management_tokens (
  token_id text primary key,
  agent_id text not null references agents(agent_id),
  token_ciphertext text not null,
  token_fingerprint varchar(128) not null,
  status management_token_status not null default 'active',
  rotated_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists management_sessions (
  session_id text primary key,
  agent_id text not null references agents(agent_id),
  label varchar(64),
  cookie_hash varchar(255) not null,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists stepup_challenges (
  challenge_id text primary key,
  agent_id text not null references agents(agent_id),
  code_hash varchar(255) not null,
  issued_for stepup_issued_for not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  failed_attempts int not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists stepup_sessions (
  stepup_session_id text primary key,
  agent_id text not null references agents(agent_id),
  management_session_id text not null references management_sessions(session_id),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists management_audit_log (
  audit_id text primary key,
  agent_id text not null references agents(agent_id),
  management_session_id text references management_sessions(session_id),
  action_type varchar(64) not null,
  action_status management_action_status not null,
  public_redacted_payload jsonb not null default '{}'::jsonb,
  private_payload jsonb not null default '{}'::jsonb,
  user_agent text,
  created_at timestamptz not null default now()
);

create table if not exists offdex_settlement_intents (
  settlement_intent_id text primary key,
  chain_key varchar(64) not null,
  maker_agent_id text not null references agents(agent_id),
  taker_agent_id text references agents(agent_id),
  maker_wallet_address varchar(128) not null,
  taker_wallet_address varchar(128),
  maker_token varchar(128) not null,
  taker_token varchar(128) not null,
  maker_amount numeric not null,
  taker_amount numeric not null,
  escrow_contract varchar(128) not null,
  escrow_deal_id varchar(128),
  maker_fund_tx_hash varchar(128),
  taker_fund_tx_hash varchar(128),
  settlement_tx_hash varchar(128),
  status offdex_settlement_status not null,
  failure_code varchar(64),
  failure_message text,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Compatibility tables retained for existing contract artifacts.
create table if not exists approvals (
  approval_id text primary key,
  agent_id text not null references agents(agent_id),
  chain_key varchar(64) not null,
  scope approval_scope not null,
  status approval_status not null,
  trade_ref text,
  pair_ref varchar(128),
  requires_stepup boolean not null default false,
  granted_by_session_id text,
  direction varchar(32) not null default 'non_directional',
  max_amount_usd numeric(18, 8) not null,
  slippage_bps_max int not null,
  resubmit_window_sec int not null default 600,
  resubmit_amount_tolerance_bps int not null default 1000,
  max_retries int not null default 3,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint approval_scope_ref_check check (
    (scope = 'trade' and trade_ref is not null) or
    (scope = 'pair' and pair_ref is not null) or
    (scope = 'global' and trade_ref is null and pair_ref is null)
  )
);

create table if not exists copy_intents (
  intent_id text primary key,
  leader_agent_id text not null references agents(agent_id),
  follower_agent_id text not null references agents(agent_id),
  source_trade_id text not null,
  source_tx_hash varchar(128),
  mode policy_mode not null,
  chain_key varchar(64) not null,
  pair varchar(128) not null,
  token_in varchar(128) not null,
  token_out varchar(128) not null,
  target_amount_usd numeric not null,
  leader_amount_usd numeric not null,
  sequence bigint not null,
  leader_confirmed_at timestamptz not null,
  expires_at timestamptz not null,
  status varchar(32) not null,
  rejection_code varchar(64),
  rejection_message text,
  created_at timestamptz not null default now(),
  unique (follower_agent_id, sequence)
);

-- append-only enforcement for management audit log
create or replace function forbid_management_audit_mutation()
returns trigger
language plpgsql
as $$
begin
  raise exception 'management_audit_log is append-only';
end;
$$;

drop trigger if exists management_audit_no_update on management_audit_log;
create trigger management_audit_no_update
before update on management_audit_log
for each row
execute function forbid_management_audit_mutation();

drop trigger if exists management_audit_no_delete on management_audit_log;
create trigger management_audit_no_delete
before delete on management_audit_log
for each row
execute function forbid_management_audit_mutation();

create index if not exists idx_trades_agent_created_at on trades(agent_id, created_at desc);
create index if not exists idx_agents_agent_name on agents(agent_name);
create index if not exists idx_agent_wallets_address on agent_wallets(address);
create index if not exists idx_agent_events_created_at on agent_events(created_at desc);
create index if not exists idx_management_tokens_agent_status on management_tokens(agent_id, status);
create index if not exists idx_management_sessions_agent_expiry on management_sessions(agent_id, expires_at);
create index if not exists idx_stepup_challenges_agent_expiry on stepup_challenges(agent_id, expires_at, consumed_at);
create index if not exists idx_stepup_sessions_agent_expiry on stepup_sessions(agent_id, expires_at);
create index if not exists idx_management_audit_agent_created_at on management_audit_log(agent_id, created_at desc);
create index if not exists idx_offdex_intents_maker_created_at on offdex_settlement_intents(maker_agent_id, created_at desc);
create index if not exists idx_offdex_intents_taker_created_at on offdex_settlement_intents(taker_agent_id, created_at desc);
create index if not exists idx_offdex_intents_status_expires_at on offdex_settlement_intents(status, expires_at);
create index if not exists idx_copy_intents_follower_status on copy_intents(follower_agent_id, status, created_at desc);
