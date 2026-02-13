alter table performance_snapshots
  add column if not exists mode policy_mode not null default 'mock',
  add column if not exists chain_key varchar(64) not null default 'all',
  add column if not exists score numeric,
  add column if not exists self_trades_count int not null default 0,
  add column if not exists copied_trades_count int not null default 0,
  add column if not exists self_volume_usd numeric,
  add column if not exists copied_volume_usd numeric,
  add column if not exists self_pnl_usd numeric,
  add column if not exists copied_pnl_usd numeric,
  add column if not exists stale boolean not null default false,
  add column if not exists degraded_reason varchar(64);

alter table copy_intents
  add column if not exists follower_trade_id text references trades(trade_id),
  add column if not exists updated_at timestamptz not null default now();

create unique index if not exists idx_copy_subscriptions_unique_pair
  on copy_subscriptions(leader_agent_id, follower_agent_id);

create index if not exists idx_perf_snapshots_window_mode_chain_created
  on performance_snapshots("window", mode, chain_key, created_at desc);

create index if not exists idx_perf_snapshots_agent_window_mode_chain_created
  on performance_snapshots(agent_id, "window", mode, chain_key, created_at desc);

create index if not exists idx_copy_intents_source_follower
  on copy_intents(source_trade_id, follower_agent_id);

create index if not exists idx_copy_intents_status_expires
  on copy_intents(status, expires_at);
