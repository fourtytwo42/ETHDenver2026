-- Slice 34: Telegram Approvals (Inline Button Approve) + Web UI Sync

create table if not exists agent_chain_approval_channels (
  channel_policy_id text primary key,
  agent_id text not null references agents(agent_id),
  chain_key varchar(64) not null,
  channel varchar(32) not null,
  enabled boolean not null default false,
  secret_hash text,
  created_by_management_session_id text references management_sessions(session_id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (agent_id, chain_key, channel)
);

create index if not exists agent_chain_approval_channels_agent_chain_idx
  on agent_chain_approval_channels (agent_id, chain_key);

create table if not exists trade_approval_prompts (
  prompt_id text primary key,
  trade_id text not null references trades(trade_id),
  agent_id text not null references agents(agent_id),
  chain_key varchar(64) not null,
  channel varchar(32) not null,
  to_address text not null,
  thread_id text,
  message_id text not null,
  created_at timestamptz not null default now(),
  deleted_at timestamptz,
  delete_error text,
  unique (trade_id, channel)
);

create index if not exists trade_approval_prompts_agent_chain_idx
  on trade_approval_prompts (agent_id, chain_key);

