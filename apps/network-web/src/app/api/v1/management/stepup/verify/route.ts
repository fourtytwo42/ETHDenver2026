import type { NextRequest } from 'next/server';

import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { requireManagementWriteAuth } from '@/lib/management-auth';
import { setStepupCookie } from '@/lib/management-cookies';
import { verifyStepupChallenge } from '@/lib/management-service';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type StepupVerifyRequest = {
  agentId: string;
  code: string;
};

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<StepupVerifyRequest>('stepup-verify-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Step-up verify payload does not match schema.',
          actionHint: 'Provide agentId and code.',
          details: validated.details
        },
        requestId
      );
    }

    const auth = await requireManagementWriteAuth(req, requestId, validated.data.agentId);
    if (!auth.ok) {
      return auth.response;
    }

    const result = await verifyStepupChallenge({
      agentId: validated.data.agentId,
      code: validated.data.code,
      managementSessionId: auth.session.sessionId,
      userAgent: req.headers.get('user-agent')
    });

    if (!result.ok) {
      return errorResponse(result.error.status, result.error, requestId);
    }

    const response = successResponse(
      {
        ok: true,
        stepup: {
          expiresAt: result.data.expiresAt
        }
      },
      200,
      requestId
    );

    setStepupCookie(response, req, result.data.stepupCookieValue);
    return response;
  } catch {
    return internalErrorResponse(requestId);
  }
}
