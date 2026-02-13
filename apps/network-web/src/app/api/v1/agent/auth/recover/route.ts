import type { NextRequest } from 'next/server';
import { verifyMessage } from 'ethers';

import { issueSignedAgentToken } from '@/lib/agent-token';
import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type AgentAuthRecoverRequest = {
  agentId: string;
  chainKey: string;
  walletAddress: string;
  challengeId: string;
  signature: string;
};

type ChallengeRow = {
  challenge_id: string;
  agent_id: string;
  chain_key: string;
  wallet_address: string;
  challenge_message: string;
  expires_at: string;
  consumed_at: string | null;
};

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<AgentAuthRecoverRequest>('agent-auth-recover-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Recover payload does not match schema.',
          actionHint: 'Provide agentId, chainKey, walletAddress, challengeId, and signature.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;
    const result = await withTransaction(async (client) => {
      const found = await client.query<ChallengeRow>(
        `
        select challenge_id, agent_id, chain_key, wallet_address, challenge_message, expires_at, consumed_at
        from agent_auth_challenges
        where challenge_id = $1
          and agent_id = $2
          and chain_key = $3
        limit 1
        `,
        [body.challengeId, body.agentId, body.chainKey]
      );

      const challenge = found.rows[0] ?? null;
      if (!challenge) {
        return { ok: false as const, reason: 'challenge_missing' };
      }

      if (challenge.consumed_at) {
        return { ok: false as const, reason: 'challenge_used' };
      }

      const expiresAt = new Date(challenge.expires_at).getTime();
      if (!Number.isFinite(expiresAt) || Date.now() > expiresAt) {
        return { ok: false as const, reason: 'challenge_expired' };
      }

      if (challenge.wallet_address.toLowerCase() !== body.walletAddress.toLowerCase()) {
        return { ok: false as const, reason: 'wallet_mismatch' };
      }

      const recoveredAddress = verifyMessage(challenge.challenge_message, body.signature);
      if (!recoveredAddress || recoveredAddress.toLowerCase() !== body.walletAddress.toLowerCase()) {
        return { ok: false as const, reason: 'signature_invalid' };
      }

      await client.query(
        `
        update agent_auth_challenges
        set consumed_at = now(), updated_at = now()
        where challenge_id = $1
        `,
        [body.challengeId]
      );

      return { ok: true as const };
    });

    if (!result.ok) {
      if (result.reason === 'challenge_missing') {
        return errorResponse(
          404,
          {
            code: 'payload_invalid',
            message: 'Recovery challenge was not found.',
            actionHint: 'Request a fresh challenge and retry recovery.'
          },
          requestId
        );
      }

      if (result.reason === 'challenge_used' || result.reason === 'challenge_expired') {
        return errorResponse(
          409,
          {
            code: 'payload_invalid',
            message: 'Recovery challenge is expired or already consumed.',
            actionHint: 'Request a fresh challenge and retry recovery.'
          },
          requestId
        );
      }

      if (result.reason === 'wallet_mismatch' || result.reason === 'signature_invalid') {
        return errorResponse(
          401,
          {
            code: 'auth_invalid',
            message: 'Wallet signature verification failed for recovery request.',
            actionHint: 'Sign the exact challenge message with the registered wallet key.'
          },
          requestId
        );
      }
    }

    const agentApiKey = issueSignedAgentToken(body.agentId);
    if (!agentApiKey) {
      return errorResponse(
        503,
        {
          code: 'internal_error',
          message: 'Agent token signer is not configured on server.',
          actionHint: 'Set XCLAW_AGENT_TOKEN_SIGNING_KEY (or XCLAW_MANAGEMENT_TOKEN_ENC_KEY) and retry.'
        },
        requestId
      );
    }

    return successResponse(
      {
        ok: true,
        agentId: body.agentId,
        agentApiKey,
        recovered: true
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
