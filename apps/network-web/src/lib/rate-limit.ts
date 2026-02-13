import type { NextRequest } from 'next/server';

import { errorResponse } from '@/lib/errors';
import { getRedisClient } from '@/lib/redis';

const WINDOW_SECONDS = 60;
const PREFIX = 'xclaw:ratelimit:v1';

function getClientIp(req: NextRequest): string {
  const forwarded = req.headers.get('x-forwarded-for');
  if (forwarded && forwarded.trim().length > 0) {
    return forwarded.split(',')[0]?.trim() ?? 'unknown';
  }

  const realIp = req.headers.get('x-real-ip');
  if (realIp && realIp.trim().length > 0) {
    return realIp.trim();
  }

  return 'unknown';
}

type LimitInput = {
  scope: string;
  key: string;
  limit: number;
  requestId: string;
};

async function checkLimit(input: LimitInput): Promise<{ ok: true } | { ok: false; response: Response }> {
  const bucket = Math.floor(Date.now() / 1000 / WINDOW_SECONDS);
  const redisKey = `${PREFIX}:${input.scope}:${input.key}:${bucket}`;

  try {
    const redis = await getRedisClient();
    const count = await redis.incr(redisKey);
    if (count === 1) {
      await redis.expire(redisKey, WINDOW_SECONDS + 2);
    }

    if (count > input.limit) {
      const retryAfter = WINDOW_SECONDS;
      return {
        ok: false,
        response: errorResponse(
          429,
          {
            code: 'rate_limited',
            message: 'Rate limit exceeded for this endpoint.',
            actionHint: 'Wait before retrying this request.',
            details: {
              scope: input.scope,
              limitPerMinute: input.limit,
              retryAfterSeconds: retryAfter
            }
          },
          input.requestId,
          { 'retry-after': String(retryAfter) }
        )
      };
    }

    return { ok: true };
  } catch {
    // Fail open on limiter backend error for MVP availability.
    return { ok: true };
  }
}

export async function enforcePublicReadRateLimit(req: NextRequest, requestId: string): Promise<{ ok: true } | { ok: false; response: Response }> {
  const ip = getClientIp(req);
  return checkLimit({
    scope: 'public_read',
    key: ip,
    limit: 120,
    requestId
  });
}

export async function enforceSensitiveManagementWriteRateLimit(
  req: NextRequest,
  requestId: string,
  agentId: string,
  sessionId: string
): Promise<{ ok: true } | { ok: false; response: Response }> {
  const ip = getClientIp(req);
  return checkLimit({
    scope: 'management_sensitive_write',
    key: `${agentId}:${sessionId}:${ip}`,
    limit: 10,
    requestId
  });
}
