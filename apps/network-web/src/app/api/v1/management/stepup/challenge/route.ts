import type { NextRequest } from 'next/server';

import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { requireManagementWriteAuth } from '@/lib/management-auth';
import { createStepupChallenge } from '@/lib/management-service';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type StepupChallengeRequest = {
  agentId: string;
  issuedFor: 'withdraw' | 'approval_scope_change' | 'sensitive_action';
};

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<StepupChallengeRequest>('stepup-challenge-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Step-up challenge payload does not match schema.',
          actionHint: 'Provide agentId and issuedFor values from the contract enum.',
          details: validated.details
        },
        requestId
      );
    }

    const auth = await requireManagementWriteAuth(req, requestId, validated.data.agentId);
    if (!auth.ok) {
      return auth.response;
    }

    const result = await createStepupChallenge({
      agentId: validated.data.agentId,
      issuedFor: validated.data.issuedFor,
      managementSessionId: auth.session.sessionId,
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
        expiresAt: result.data.expiresAt
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
