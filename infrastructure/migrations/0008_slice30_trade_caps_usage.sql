alter table if exists agent_policy_snapshots
  add column if not exists daily_cap_usd_enabled boolean not null default true,
  add column if not exists daily_trade_cap_enabled boolean not null default true,
  add column if not exists max_daily_trade_count integer;

create table if not exists agent_daily_trade_usage (
  usage_id text primary key,
  agent_id text not null references agents(agent_id),
  chain_key varchar(64) not null,
  utc_day date not null,
  daily_spend_usd numeric not null default 0,
  daily_filled_trades integer not null default 0,
  updated_at timestamptz not null default now(),
  unique (agent_id, chain_key, utc_day)
);

create index if not exists idx_agent_daily_trade_usage_agent_chain_day
  on agent_daily_trade_usage(agent_id, chain_key, utc_day desc);
