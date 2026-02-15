import type { NextRequest } from 'next/server';

import { requireAgentAuth } from '@/lib/agent-auth';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { createStepupChallenge } from '@/lib/management-service';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type AgentStepupChallengeRequest = {
  agentId: string;
  issuedFor?: 'withdraw' | 'approval_scope_change' | 'sensitive_action';
};

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<AgentStepupChallengeRequest>('agent-stepup-challenge-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Agent step-up challenge payload does not match schema.',
          actionHint: 'Provide agentId and optional issuedFor enum.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;
    const auth = requireAgentAuth(req, body.agentId, requestId);
    if (!auth.ok) {
      return auth.response;
    }

    const result = await createStepupChallenge({
      agentId: body.agentId,
      issuedFor: body.issuedFor ?? 'sensitive_action',
      managementSessionId: null,
      userAgent: req.headers.get('user-agent')
    });

    if (!result.ok) {
      return errorResponse(result.error.status, result.error, requestId);
    }

    return successResponse(
      {
        ok: true,
        challengeId: result.data.challengeId,
        code: result.data.code,
        expiresAt: result.data.expiresAt,
        issuedFor: body.issuedFor ?? 'sensitive_action'
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
