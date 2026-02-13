import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const fixturesPath = path.join(root, 'infrastructure', 'seed-data', 'fixtures.json');
const statePath = path.join(root, 'infrastructure', 'seed-data', '.seed-state.json');
const required = ['happy_path', 'approval_retry', 'degraded_rpc', 'copy_reject'];

const fixtures = JSON.parse(fs.readFileSync(fixturesPath, 'utf8'));
const missing = required.filter((k) => !fixtures.scenarios?.[k]);

if (missing.length > 0) {
  console.error(JSON.stringify({ ok: false, action: 'seed:verify', error: 'missing required scenarios', missing }, null, 2));
  process.exit(1);
}

if (!fs.existsSync(statePath)) {
  console.error(JSON.stringify({ ok: false, action: 'seed:verify', error: 'seed state missing; run npm run seed:load first' }, null, 2));
  process.exit(1);
}

const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
if (!state.seedMode || !Array.isArray(state.scenarios) || state.scenarios.length < required.length) {
  console.error(JSON.stringify({ ok: false, action: 'seed:verify', error: 'invalid seed state', state }, null, 2));
  process.exit(1);
}

console.log(JSON.stringify({ ok: true, action: 'seed:verify', requiredScenarios: required, totals: state.totals }, null, 2));
