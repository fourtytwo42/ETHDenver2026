import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const statePath = path.join(root, 'infrastructure', 'seed-data', '.seed-state.json');
const liveLogPath = path.join(root, 'infrastructure', 'seed-data', 'live-activity.log');

if (fs.existsSync(statePath)) fs.rmSync(statePath);
if (fs.existsSync(liveLogPath)) fs.rmSync(liveLogPath);

console.log(JSON.stringify({ ok: true, action: 'seed:reset', removed: ['.seed-state.json', 'live-activity.log'] }, null, 2));
