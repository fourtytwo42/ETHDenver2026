do $$
begin
  if not exists (select 1 from pg_type where typname = 'outbound_transfer_mode') then
    create type outbound_transfer_mode as enum ('disabled', 'allow_all', 'whitelist');
  end if;
end
$$;

create table if not exists agent_transfer_policies (
  policy_id text primary key,
  agent_id text not null references agents(agent_id),
  chain_key varchar(64) not null,
  outbound_transfers_enabled boolean not null default false,
  outbound_mode outbound_transfer_mode not null default 'disabled',
  outbound_whitelist_addresses jsonb not null default '[]'::jsonb,
  updated_by_management_session_id text references management_sessions(session_id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (agent_id, chain_key)
);

create index if not exists idx_agent_transfer_policies_agent_chain
  on agent_transfer_policies(agent_id, chain_key);

