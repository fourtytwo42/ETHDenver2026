import { Pool } from 'pg';
import type { PoolClient, QueryResult, QueryResultRow } from 'pg';

import { getEnv } from '@/lib/env';

declare global {
  // eslint-disable-next-line no-var
  var __xclawPgPool: unknown | undefined;
}

function createPool() {
  const env = getEnv();
  return new Pool({
    connectionString: env.databaseUrl,
    max: 10
  });
}

function getPool(): {
  query: <T extends QueryResultRow = QueryResultRow>(text: string, params?: unknown[]) => Promise<QueryResult<T>>;
  connect: () => Promise<PoolClient>;
} {
  if (!globalThis.__xclawPgPool) {
    globalThis.__xclawPgPool = createPool();
  }
  return globalThis.__xclawPgPool as {
    query: <T extends QueryResultRow = QueryResultRow>(text: string, params?: unknown[]) => Promise<QueryResult<T>>;
    connect: () => Promise<PoolClient>;
  };
}

export async function dbQuery<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params: unknown[] = []
): Promise<QueryResult<T>> {
  return getPool().query<T>(text, params);
}

export async function withTransaction<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
