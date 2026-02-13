-- Slice 17: deposit tracking + limit orders

do $$
begin
  if not exists (select 1 from pg_type where typname = 'limit_order_side') then
    create type limit_order_side as enum ('buy', 'sell');
  end if;
  if not exists (select 1 from pg_type where typname = 'limit_order_status') then
    create type limit_order_status as enum ('open', 'triggered', 'filled', 'failed', 'cancelled', 'expired');
  end if;
  if not exists (select 1 from pg_type where typname = 'limit_order_trigger_source') then
    create type limit_order_trigger_source as enum ('management_api', 'agent_local');
  end if;
  if not exists (select 1 from pg_type where typname = 'limit_order_execution_status') then
    create type limit_order_execution_status as enum ('queued', 'executing', 'filled', 'failed');
  end if;
end
$$;

create table if not exists wallet_balance_snapshots (
  snapshot_id text primary key,
  agent_id text not null references agents(agent_id),
  chain_key varchar(64) not null,
  token varchar(128) not null,
  balance numeric not null,
  block_number bigint,
  observed_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  unique (agent_id, chain_key, token)
);

create table if not exists deposit_events (
  deposit_event_id text primary key,
  agent_id text not null references agents(agent_id),
  chain_key varchar(64) not null,
  token varchar(128) not null,
  amount numeric not null,
  tx_hash varchar(128) not null,
  log_index int not null default 0,
  block_number bigint not null,
  confirmed_at timestamptz not null,
  status varchar(32) not null default 'confirmed',
  created_at timestamptz not null default now(),
  unique (chain_key, tx_hash, log_index, token)
);

create table if not exists limit_orders (
  order_id text primary key,
  agent_id text not null references agents(agent_id),
  chain_key varchar(64) not null,
  mode policy_mode not null default 'real',
  side limit_order_side not null,
  token_in varchar(128) not null,
  token_out varchar(128) not null,
  amount_in numeric not null,
  limit_price numeric not null,
  slippage_bps int not null,
  status limit_order_status not null default 'open',
  expires_at timestamptz,
  cancelled_at timestamptz,
  trigger_source limit_order_trigger_source not null default 'management_api',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists limit_order_attempts (
  attempt_id text primary key,
  order_id text not null references limit_orders(order_id),
  trade_id text references trades(trade_id),
  trigger_price numeric,
  trigger_at timestamptz not null,
  execution_status limit_order_execution_status not null,
  reason_code varchar(64),
  reason_message text,
  tx_hash varchar(128),
  mock_receipt_id varchar(128),
  created_at timestamptz not null default now()
);

create index if not exists idx_wallet_balance_snapshots_agent_chain_token
  on wallet_balance_snapshots(agent_id, chain_key, token);

create index if not exists idx_deposit_events_agent_chain_created
  on deposit_events(agent_id, chain_key, created_at desc);

create index if not exists idx_limit_orders_agent_chain_status_created
  on limit_orders(agent_id, chain_key, status, created_at desc);

create index if not exists idx_limit_orders_status_expires
  on limit_orders(status, expires_at);

create index if not exists idx_limit_order_attempts_order_created
  on limit_order_attempts(order_id, created_at desc);
