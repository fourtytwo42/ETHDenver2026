import type { NextRequest } from 'next/server';

import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { makeId } from '@/lib/ids';
import { requireManagementWriteAuth } from '@/lib/management-auth';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type ResumeRequest = {
  agentId: string;
  force?: boolean;
};

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<ResumeRequest>('management-resume-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Resume payload does not match schema.',
          actionHint: 'Provide agentId.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;
    const auth = await requireManagementWriteAuth(req, requestId, body.agentId);
    if (!auth.ok) {
      return auth.response;
    }

    const result = await withTransaction(async (client) => {
      const policy = await client.query<{ snapshot_id: string }>(
        `
        select snapshot_id
        from agent_policy_snapshots
        where agent_id = $1
        order by created_at desc
        limit 1
        `,
        [body.agentId]
      );

      if (policy.rowCount === 0 && !body.force) {
        await client.query(
          `
          update agents
          set public_status = 'degraded'::public_status,
              updated_at = now()
          where agent_id = $1
          `,
          [body.agentId]
        );

        await client.query(
          `
          insert into management_audit_log (
            audit_id, agent_id, management_session_id, action_type, action_status,
            public_redacted_payload, private_payload, user_agent, created_at
          ) values ($1, $2, $3, 'agent.resume', 'failed', $4::jsonb, $5::jsonb, $6, now())
          `,
          [
            makeId('aud'),
            body.agentId,
            auth.session.sessionId,
            JSON.stringify({ status: 'expired/requires-reauthorization' }),
            JSON.stringify({ cause: 'policy_snapshot_missing' }),
            req.headers.get('user-agent')
          ]
        );

        return { ok: false as const };
      }

      await client.query(
        `
        update agents
        set public_status = 'active'::public_status,
            updated_at = now()
        where agent_id = $1
        `,
        [body.agentId]
      );

      await client.query(
        `
        insert into management_audit_log (
          audit_id, agent_id, management_session_id, action_type, action_status,
          public_redacted_payload, private_payload, user_agent, created_at
        ) values ($1, $2, $3, 'agent.resume', 'accepted', $4::jsonb, $5::jsonb, $6, now())
        `,
        [
          makeId('aud'),
          body.agentId,
          auth.session.sessionId,
          JSON.stringify({ publicStatus: 'active' }),
          JSON.stringify({ policySnapshotValidated: true }),
          req.headers.get('user-agent')
        ]
      );

      return { ok: true as const };
    });

    if (!result.ok) {
      return errorResponse(
        409,
        {
          code: 'auth_expired',
          message: 'Resume validation failed: expired/requires-reauthorization.',
          actionHint: 'Refresh policy/session context, then retry resume.'
        },
        requestId
      );
    }

    return successResponse({ ok: true, publicStatus: 'active' }, 200, requestId);
  } catch {
    return internalErrorResponse(requestId);
  }
}
