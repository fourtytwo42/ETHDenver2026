import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const migrationDir = path.join(root, 'infrastructure', 'migrations');
const migrationFiles = fs
  .readdirSync(migrationDir)
  .filter((file) => file.endsWith('.sql'))
  .sort();

const sql = migrationFiles
  .map((file) => fs.readFileSync(path.join(migrationDir, file), 'utf8'))
  .join('\n')
  .toLowerCase();

const requiredTables = [
  'agents',
  'agent_wallets',
  'agent_policy_snapshots',
  'trades',
  'agent_events',
  'performance_snapshots',
  'copy_subscriptions',
  'management_tokens',
  'management_sessions',
  'stepup_challenges',
  'stepup_sessions',
  'management_audit_log',
  'offdex_settlement_intents',
  'approvals',
  'copy_intents'
];

const requiredEnums = [
  'runtime_platform',
  'public_status',
  'custody_type',
  'policy_mode',
  'policy_approval_mode',
  'trade_status',
  'agent_event_type',
  'performance_window',
  'management_token_status',
  'stepup_issued_for',
  'management_action_status',
  'approval_scope',
  'approval_status',
  'offdex_settlement_status'
];

const requiredChecks = [
  'forbid_management_audit_mutation',
  'create trigger management_audit_no_update',
  'create trigger management_audit_no_delete',
  'idx_trades_agent_created_at',
  'idx_offdex_intents_status_expires_at',
  'idx_management_audit_agent_created_at',
  'alter table performance_snapshots',
  'add column if not exists mode policy_mode',
  'add column if not exists chain_key varchar(64)',
  'alter table copy_intents',
  'add column if not exists follower_trade_id text references trades(trade_id)',
  'idx_perf_snapshots_window_mode_chain_created',
  'idx_copy_subscriptions_unique_pair'
];

const missingTables = requiredTables.filter((t) => !sql.includes(`create table if not exists ${t}`));
const missingEnums = requiredEnums.filter((e) => !sql.includes(`create type ${e} as enum`));
const missingChecks = requiredChecks.filter((c) => !sql.includes(c));

const ok = missingTables.length === 0 && missingEnums.length === 0 && missingChecks.length === 0;
const report = {
  ok,
  missingTables,
  missingEnums,
  missingChecks,
  migrationFiles,
  checkedAt: new Date().toISOString()
};

if (!ok) {
  console.error(JSON.stringify(report, null, 2));
  process.exit(1);
}

console.log(JSON.stringify(report, null, 2));
