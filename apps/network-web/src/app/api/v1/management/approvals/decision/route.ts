import type { NextRequest } from 'next/server';

import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { makeId } from '@/lib/ids';
import { requireManagementWriteAuth } from '@/lib/management-auth';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type ApprovalDecisionRequest = {
  agentId: string;
  tradeId: string;
  decision: 'approve' | 'reject';
  reasonCode?: string;
  reasonMessage?: string;
};

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<ApprovalDecisionRequest>('management-approval-decision-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Approval decision payload does not match schema.',
          actionHint: 'Provide agentId, tradeId, and decision.',
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

    const targetStatus = body.decision === 'approve' ? 'approved' : 'rejected';
    const eventType = body.decision === 'approve' ? 'trade_approved' : 'trade_rejected';

    const result = await withTransaction(async (client) => {
      const trade = await client.query<{ status: string; chain_key: string }>(
        `
        select status, chain_key
        from trades
        where trade_id = $1
          and agent_id = $2
        limit 1
        `,
        [body.tradeId, body.agentId]
      );

      if (trade.rowCount === 0) {
        return { ok: false as const, kind: 'missing' as const };
      }

      const currentStatus = trade.rows[0].status;
      if (currentStatus !== 'approval_pending') {
        return { ok: false as const, kind: 'transition' as const, currentStatus };
      }

      await client.query(
        `
        update trades
        set
          status = $1::trade_status,
          reason_code = $2,
          reason_message = $3,
          updated_at = now()
        where trade_id = $4
        `,
        [targetStatus, body.reasonCode ?? null, body.reasonMessage ?? null, body.tradeId]
      );

      await client.query(
        `
        insert into agent_events (event_id, agent_id, trade_id, event_type, payload, created_at)
        values ($1, $2, $3, $4, $5::jsonb, now())
        `,
        [
          makeId('evt'),
          body.agentId,
          body.tradeId,
          eventType,
          JSON.stringify({
            decision: body.decision,
            reasonCode: body.reasonCode ?? null,
            reasonMessage: body.reasonMessage ?? null,
            managedBySessionId: auth.session.sessionId
          })
        ]
      );

      await client.query(
        `
        insert into management_audit_log (
          audit_id, agent_id, management_session_id, action_type, action_status,
          public_redacted_payload, private_payload, user_agent, created_at
        ) values ($1, $2, $3, 'approval.decision', 'accepted', $4::jsonb, $5::jsonb, $6, now())
        `,
        [
          makeId('aud'),
          body.agentId,
          auth.session.sessionId,
          JSON.stringify({ tradeId: body.tradeId, decision: body.decision }),
          JSON.stringify({ reasonCode: body.reasonCode ?? null, reasonMessage: body.reasonMessage ?? null }),
          req.headers.get('user-agent')
        ]
      );

      return { ok: true as const, status: targetStatus };
    });

    if (!result.ok) {
      if (result.kind === 'missing') {
        return errorResponse(
          404,
          {
            code: 'payload_invalid',
            message: 'Trade was not found for this agent.',
            actionHint: 'Verify tradeId and retry.'
          },
          requestId
        );
      }

      return errorResponse(
        409,
        {
          code: 'trade_invalid_transition',
          message: 'Trade is not in approval_pending state.',
          actionHint: 'Refresh queue and retry only pending items.',
          details: { currentStatus: result.currentStatus }
        },
        requestId
      );
    }

    return successResponse(
      {
        ok: true,
        tradeId: body.tradeId,
        status: result.status
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
