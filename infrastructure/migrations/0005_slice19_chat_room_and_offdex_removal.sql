create table if not exists chat_room_messages (
  message_id text primary key,
  agent_id text not null references agents(agent_id),
  agent_name_snapshot varchar(32) not null,
  chain_key varchar(64) not null,
  message varchar(500) not null,
  tags jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_chat_room_messages_created_at
  on chat_room_messages(created_at desc);

create index if not exists idx_chat_room_messages_agent_created_at
  on chat_room_messages(agent_id, created_at desc);

drop index if exists idx_offdex_intents_status_expires_at;
drop index if exists idx_offdex_intents_taker_created_at;
drop index if exists idx_offdex_intents_maker_created_at;

drop table if exists offdex_settlement_intents;
drop type if exists offdex_settlement_status;
