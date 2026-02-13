import { createHash } from 'node:crypto';

import type { NextRequest } from 'next/server';

import { getEnv } from '@/lib/env';
import { errorResponse } from '@/lib/errors';
import { getRedisClient } from '@/lib/redis';

type StoredIdempotencyResponse = {
  status: number;
  body: unknown;
};

type StoredIdempotencyRecord = {
  fingerprint: string;
  response?: StoredIdempotencyResponse;
};

type IdempotencyContext = {
  redisKey: string;
  record: StoredIdempotencyRecord;
  replayResponse: StoredIdempotencyResponse | null;
};

function stableStringify(input: unknown): string {
  if (input === null || typeof input !== 'object') {
    return JSON.stringify(input);
  }

  if (Array.isArray(input)) {
    return `[${input.map((item) => stableStringify(item)).join(',')}]`;
  }

  const entries = Object.entries(input as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
  return `{${entries.map(([key, value]) => `${JSON.stringify(key)}:${stableStringify(value)}`).join(',')}}`;
}

function buildFingerprint(method: string, path: string, body: unknown): string {
  const digest = createHash('sha256');
  digest.update(method);
  digest.update(path);
  digest.update(stableStringify(body));
  return digest.digest('hex');
}

export async function ensureIdempotency(
  req: NextRequest,
  routeName: string,
  agentId: string,
  body: unknown,
  requestId: string
): Promise<{ ok: true; ctx: IdempotencyContext } | { ok: false; response: Response }> {
  const idempotencyKey = req.headers.get('idempotency-key');
  if (!idempotencyKey || idempotencyKey.trim().length < 8) {
    return {
      ok: false,
      response: errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Idempotency-Key header is required for write requests.',
          actionHint: 'Set Idempotency-Key to a stable unique value per logical write request.'
        },
        requestId
      )
    };
  }

  const trimmedKey = idempotencyKey.trim();
  const fingerprint = buildFingerprint(req.method, req.nextUrl.pathname, body);
  const redisKey = `xclaw:idem:v1:${routeName}:${agentId}:${trimmedKey}`;

  const client = await getRedisClient();
  const existingRaw = await client.get(redisKey);
  if (!existingRaw) {
    const record: StoredIdempotencyRecord = { fingerprint };
    const env = getEnv();
    await client.set(redisKey, JSON.stringify(record), { EX: env.idempotencyTtlSec });
    return { ok: true, ctx: { redisKey, record, replayResponse: null } };
  }

  let parsed: StoredIdempotencyRecord;
  try {
    parsed = JSON.parse(existingRaw) as StoredIdempotencyRecord;
  } catch {
    return {
      ok: false,
      response: errorResponse(
        409,
        {
          code: 'idempotency_conflict',
          message: 'Idempotency key is already associated with a conflicting request.',
          actionHint: 'Generate a new Idempotency-Key for this request.'
        },
        requestId
      )
    };
  }

  if (parsed.fingerprint !== fingerprint) {
    return {
      ok: false,
      response: errorResponse(
        409,
        {
          code: 'idempotency_conflict',
          message: 'Idempotency key reuse conflict detected for a different payload.',
          actionHint: 'Use a new Idempotency-Key when request payload changes.'
        },
        requestId
      )
    };
  }

  return {
    ok: true,
    ctx: {
      redisKey,
      record: parsed,
      replayResponse: parsed.response ?? null
    }
  };
}

export async function storeIdempotencyResponse(ctx: IdempotencyContext, status: number, body: unknown): Promise<void> {
  const client = await getRedisClient();
  const env = getEnv();
  const nextRecord: StoredIdempotencyRecord = {
    fingerprint: ctx.record.fingerprint,
    response: {
      status,
      body
    }
  };
  await client.set(ctx.redisKey, JSON.stringify(nextRecord), { EX: env.idempotencyTtlSec });
}
