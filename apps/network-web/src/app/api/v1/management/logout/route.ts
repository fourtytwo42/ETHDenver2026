import type { NextRequest } from 'next/server';

import { dbQuery } from '@/lib/db';
import { internalErrorResponse, successResponse } from '@/lib/errors';
import { makeId } from '@/lib/ids';
import { requireManagementSession } from '@/lib/management-auth';
import { clearAllManagementCookies } from '@/lib/management-cookies';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const auth = await requireManagementSession(req, requestId);
    const response = successResponse({ ok: true }, 200, requestId);

    if (auth.ok) {
      await dbQuery(
        `
        insert into management_audit_log (
          audit_id, agent_id, management_session_id, action_type, action_status,
          public_redacted_payload, private_payload, user_agent, created_at
        ) values ($1, $2, $3, 'session.logout', 'accepted', $4::jsonb, $5::jsonb, $6, now())
        `,
        [
          makeId('aud'),
          auth.session.agentId,
          auth.session.sessionId,
          JSON.stringify({ logout: true }),
          JSON.stringify({ reason: 'user_requested' }),
          req.headers.get('user-agent')
        ]
      );
    }

    clearAllManagementCookies(response, req);
    return response;
  } catch {
    return internalErrorResponse(requestId);
  }
}
