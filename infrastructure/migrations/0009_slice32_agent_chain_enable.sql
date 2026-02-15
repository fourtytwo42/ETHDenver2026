create table if not exists agent_chain_policies (
  chain_policy_id text primary key,
  agent_id text not null references agents(agent_id),
  chain_key varchar(64) not null,
  chain_enabled boolean not null default true,
  updated_by_management_session_id text references management_sessions(session_id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (agent_id, chain_key)
);

create index if not exists idx_agent_chain_policies_agent_chain
  on agent_chain_policies(agent_id, chain_key);

