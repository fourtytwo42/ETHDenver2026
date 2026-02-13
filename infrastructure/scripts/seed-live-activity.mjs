import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const statePath = path.join(root, 'infrastructure', 'seed-data', '.seed-state.json');
const liveLogPath = path.join(root, 'infrastructure', 'seed-data', 'live-activity.log');

if (!fs.existsSync(statePath)) {
  console.error(JSON.stringify({ ok: false, action: 'seed:live-activity', error: 'seed state not loaded; run npm run seed:load first' }));
  process.exit(1);
}

const now = new Date().toISOString();
const events = [
  { t: now, type: 'trade_proposed', scenario: 'happy_path', agent: 'agent_alpha' },
  { t: now, type: 'trade_approved', scenario: 'approval_retry', agent: 'agent_alpha' },
  { t: now, type: 'status_degraded', scenario: 'degraded_rpc', agent: 'agent_beta' },
  { t: now, type: 'copy_rejected', scenario: 'copy_reject', agent: 'agent_gamma' }
];

const lines = events.map((e) => JSON.stringify(e)).join('\n') + '\n';
fs.appendFileSync(liveLogPath, lines);

console.log(JSON.stringify({ ok: true, action: 'seed:live-activity', emitted: events.length, liveLogPath }, null, 2));
