import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import pg from 'pg';
const { Client } = pg;

const root = process.cwd();
const migrationDir = path.join(root, 'infrastructure', 'migrations');
const files = fs.readdirSync(migrationDir).filter((f) => f.endsWith('.sql')).sort();

if (!process.env.DATABASE_URL) {
  const envLocal = path.join(root, '.env.local');
  if (fs.existsSync(envLocal)) {
    const lines = fs.readFileSync(envLocal, 'utf8').split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) {
        continue;
      }
      const [key, ...rest] = trimmed.split('=');
      if (!key || process.env[key] !== undefined) {
        continue;
      }
      process.env[key] = rest.join('=').trim();
    }
  }
}

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.error(JSON.stringify({ ok: false, action: 'db:migrate', error: 'Missing required env: DATABASE_URL' }, null, 2));
  process.exit(1);
}

const client = new Client({ connectionString: databaseUrl });

try {
  await client.connect();
  await client.query(
    `
    create table if not exists schema_migrations (
      migration_file text primary key,
      applied_at timestamptz not null default now()
    )
    `,
  );

  const existing = await client.query('select migration_file from schema_migrations');
  const applied = new Set(existing.rows.map((row) => String(row.migration_file)));

  if (applied.size === 0) {
    const baseline = await client.query(`select to_regclass('public.agents') as agents, to_regclass('public.limit_orders') as limit_orders`);
    const hasAgents = Boolean(baseline.rows[0]?.agents);
    const hasLimitOrders = Boolean(baseline.rows[0]?.limit_orders);
    if (hasAgents) {
      await client.query(
        `insert into schema_migrations (migration_file, applied_at) values ('0001_xclaw_core.sql', now()) on conflict do nothing`,
      );
      await client.query(
        `insert into schema_migrations (migration_file, applied_at) values ('0002_slice13_metrics_copy.sql', now()) on conflict do nothing`,
      );
      applied.add('0001_xclaw_core.sql');
      applied.add('0002_slice13_metrics_copy.sql');
    }
    if (hasLimitOrders) {
      await client.query(
        `insert into schema_migrations (migration_file, applied_at) values ('0003_slice17_deposit_limit_orders.sql', now()) on conflict do nothing`,
      );
      applied.add('0003_slice17_deposit_limit_orders.sql');
    }
  }

  for (const file of files) {
    if (applied.has(file)) {
      continue;
    }
    const sql = fs.readFileSync(path.join(migrationDir, file), 'utf8');
    await client.query('BEGIN');
    try {
      await client.query(sql);
      await client.query('insert into schema_migrations (migration_file, applied_at) values ($1, now())', [file]);
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw new Error(`Migration failed for ${file}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        action: 'db:migrate',
        migrationFiles: files,
        appliedAt: new Date().toISOString(),
      },
      null,
      2,
    ),
  );
} catch (error) {
  console.error(
    JSON.stringify(
      {
        ok: false,
        action: 'db:migrate',
        error: error instanceof Error ? error.message : String(error),
      },
      null,
      2,
    ),
  );
  process.exit(1);
} finally {
  await client.end();
}
