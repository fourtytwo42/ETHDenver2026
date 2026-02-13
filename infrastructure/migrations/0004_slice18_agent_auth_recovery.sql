create table if not exists agent_auth_challenges (
  challenge_id text primary key,
  agent_id text not null references agents(agent_id),
  chain_key varchar(64) not null,
  wallet_address varchar(128) not null,
  nonce varchar(128) not null,
  action varchar(64) not null,
  challenge_message text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists idx_agent_auth_challenge_nonce
  on agent_auth_challenges(agent_id, nonce)
  where consumed_at is null;

create index if not exists idx_agent_auth_challenges_agent_created
  on agent_auth_challenges(agent_id, created_at desc);
