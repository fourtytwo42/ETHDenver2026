import type { NextRequest } from 'next/server';

import { getEnv } from '@/lib/env';
import { errorResponse } from '@/lib/errors';
import { verifySignedAgentToken } from '@/lib/agent-token';

type AuthFailure = {
  ok: false;
  response: Response;
};

type AuthSuccess = {
  ok: true;
  agentId: string;
};

function parseBearerToken(req: NextRequest): string | null {
  const authorization = req.headers.get('authorization');
  if (!authorization) {
    return null;
  }

  const [scheme, value] = authorization.split(' ');
  if (!scheme || !value || scheme.toLowerCase() !== 'bearer') {
    return null;
  }

  return value.trim();
}

function failMissingAuth(requestId: string): AuthFailure {
  return {
    ok: false,
    response: errorResponse(
      401,
      {
        code: 'auth_invalid',
        message: 'Authorization bearer token is required.',
        actionHint: 'Include Authorization: Bearer <agent_api_key>.'
      },
      requestId
    )
  };
}

export function authenticateAgentByToken(
  req: NextRequest,
  requestId: string,
  expectedAgentId?: string
): AuthSuccess | AuthFailure {
  const token = parseBearerToken(req);
  if (!token) {
    return failMissingAuth(requestId);
  }

  const env = getEnv();

  if (expectedAgentId) {
    const expectedToken = env.agentApiKeys[expectedAgentId];
    if (expectedToken && expectedToken === token) {
      return { ok: true, agentId: expectedAgentId };
    }

    const signed = verifySignedAgentToken(token);
    if (signed.ok && signed.agentId === expectedAgentId) {
      return { ok: true, agentId: expectedAgentId };
    }

    return {
      ok: false,
      response: errorResponse(
        401,
        {
          code: 'auth_invalid',
          message: 'Agent authentication failed for the provided agentId.',
          actionHint: 'Use the api key mapped to this agentId in XCLAW_AGENT_API_KEYS or a valid signed agent bootstrap token.'
        },
        requestId
      )
    };
  }

  for (const [agentId, candidate] of Object.entries(env.agentApiKeys)) {
    if (candidate === token) {
      return { ok: true, agentId };
    }
  }

  const signed = verifySignedAgentToken(token);
  if (signed.ok) {
    return { ok: true, agentId: signed.agentId };
  }

  return {
    ok: false,
    response: errorResponse(
      401,
      {
        code: 'auth_invalid',
        message: 'Bearer token does not match any configured agent key.',
        actionHint: 'Provide a valid bearer token from XCLAW_AGENT_API_KEYS.'
      },
      requestId
    )
  };
}

export function requireAgentAuth(req: NextRequest, requestAgentId: string, requestId: string): AuthSuccess | AuthFailure {
  return authenticateAgentByToken(req, requestId, requestAgentId);
}
