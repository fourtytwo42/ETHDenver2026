import { randomBytes } from 'node:crypto';
import type { NextRequest } from 'next/server';

import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { makeId } from '@/lib/ids';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type AgentAuthChallengeRequest = {
  agentId: string;
  chainKey: string;
  walletAddress: string;
  action: 'agent_key_recovery';
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

    const validated = validatePayload<AgentAuthChallengeRequest>('agent-auth-challenge-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Challenge payload does not match schema.',
          actionHint: 'Provide agentId, chainKey, walletAddress, and action=agent_key_recovery.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;

    const wallet = await withTransaction(async (client) => {
      const found = await client.query<{ agent_id: string; address: string }>(
        `
        select agent_id, address
        from agent_wallets
        where agent_id = $1
          and chain_key = $2
          and lower(address) = lower($3)
        limit 1
        `,
        [body.agentId, body.chainKey, body.walletAddress]
      );
      return found.rows[0] ?? null;
    });

    if (!wallet) {
      return errorResponse(
        404,
        {
          code: 'payload_invalid',
          message: 'Agent wallet is not registered for this chain.',
          actionHint: 'Register wallet ownership first, then request recovery challenge.'
        },
        requestId
      );
    }

    const challengeId = makeId('ach');
    const nonce = randomBytes(18).toString('base64url');
    const timestamp = canonicalUtcNowIso();
    const challengeMessage = makeCanonicalChallengeMessage(body.chainKey, nonce, timestamp, body.action);

    await withTransaction(async (client) => {
      await client.query(
        `
        insert into agent_auth_challenges (
          challenge_id,
          agent_id,
          chain_key,
          wallet_address,
          nonce,
          action,
          challenge_message,
          expires_at,
          consumed_at,
          created_at,
          updated_at
        )
        values ($1, $2, $3, $4, $5, $6, $7, now() + interval '5 minutes', null, now(), now())
        `,
        [challengeId, body.agentId, body.chainKey, body.walletAddress, nonce, body.action, challengeMessage]
      );
    });

    return successResponse(
      {
        ok: true,
        challengeId,
        challengeMessage,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
        scheme: 'eip191_personal_sign'
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
