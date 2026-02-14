import { randomBytes } from 'node:crypto';
import type { NextRequest } from 'next/server';

import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { makeId } from '@/lib/ids';
import { getRedisClient } from '@/lib/redis';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type AgentBootstrapChallengeRequest = {
  schemaVersion: number;
  chainKey: string;
  walletAddress: string;
};

function canonicalUtcNowIso(): string {
  return new Date().toISOString().replace('+00:00', 'Z');
}

function makeCanonicalChallengeMessage(chainKey: string, nonce: string, timestamp: string, action: string): string {
  return ['domain=xclaw.trade', `chain=${chainKey}`, `nonce=${nonce}`, `timestamp=${timestamp}`, `action=${action}`].join('\n');
}

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<AgentBootstrapChallengeRequest>('agent-bootstrap-challenge-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Bootstrap challenge payload does not match schema.',
          actionHint: 'Provide schemaVersion=1, chainKey, and walletAddress.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;
    const chainKey = body.chainKey.trim() || 'base_sepolia';
    const walletAddress = body.walletAddress.trim();

    const challengeId = makeId('bch');
    const nonce = randomBytes(18).toString('base64url');
    const timestamp = canonicalUtcNowIso();
    const challengeMessage = makeCanonicalChallengeMessage(chainKey, nonce, timestamp, 'agent_bootstrap');
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    const redis = await getRedisClient();
    const redisKey = `xclaw:bootstrap_challenge:v1:${challengeId}`;
    await redis.set(
      redisKey,
      JSON.stringify({ chainKey, walletAddress, challengeMessage, expiresAt: expiresAt.toISOString() }),
      { EX: 5 * 60 }
    );

    return successResponse(
      {
        ok: true,
        challengeId,
        challengeMessage,
        expiresAt: expiresAt.toISOString(),
        scheme: 'eip191_personal_sign'
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}

