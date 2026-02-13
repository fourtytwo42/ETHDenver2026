import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const fixturesPath = path.join(root, 'infrastructure', 'seed-data', 'fixtures.json');
const statePath = path.join(root, 'infrastructure', 'seed-data', '.seed-state.json');

const fixtures = JSON.parse(fs.readFileSync(fixturesPath, 'utf8'));
const loadedAt = new Date().toISOString();

const state = {
  seedMode: true,
  loadedAt,
  version: fixtures.version,
  scenarios: Object.keys(fixtures.scenarios),
  totals: Object.values(fixtures.scenarios).reduce(
    (acc, s) => {
      acc.agents += Number(s.agents || 0);
      acc.trades += Number(s.trades || 0);
      return acc;
    },
    { agents: 0, trades: 0 }
  )
};

fs.writeFileSync(statePath, JSON.stringify(state, null, 2));
console.log(JSON.stringify({ ok: true, action: 'seed:load', statePath, state }, null, 2));
