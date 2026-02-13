import type { NextRequest } from 'next/server';

import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { makeId } from '@/lib/ids';
import { requireManagementWriteAuth } from '@/lib/management-auth';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type CancelRequest = {
  agentId: string;
};

export async function POST(req: NextRequest, context: { params: Promise<{ orderId: string }> }) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<CancelRequest>('management-limit-order-cancel-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Limit-order cancel payload does not match schema.',
          actionHint: 'Provide agentId for order cancellation.',
          details: validated.details
        },
        requestId
      );
    }

    const { orderId } = await context.params;
    const body = validated.data;
    const auth = await requireManagementWriteAuth(req, requestId, body.agentId);
    if (!auth.ok) {
      return auth.response;
    }

    const updated = await withTransaction(async (client) => {
      const result = await client.query<{
        order_id: string;
        status: string;
      }>(
        `
        update limit_orders
        set status = 'cancelled', cancelled_at = now(), updated_at = now()
        where order_id = $1
          and agent_id = $2
          and status in ('open', 'triggered')
        returning order_id, status::text
        `,
        [orderId, body.agentId]
      );

      if (result.rowCount === 0) {
        return null;
      }

      await client.query(
        `
        insert into management_audit_log (
          audit_id, agent_id, management_session_id, action_type, action_status,
          public_redacted_payload, private_payload, user_agent, created_at
        ) values ($1, $2, $3, 'limit_order.cancel', 'accepted', $4::jsonb, $5::jsonb, $6, now())
        `,
        [
          makeId('aud'),
          body.agentId,
          auth.session.sessionId,
          JSON.stringify({ orderId }),
          JSON.stringify({ orderId }),
          req.headers.get('user-agent')
        ]
      );

      return result.rows[0];
    });

    if (!updated) {
      return errorResponse(
        404,
        {
          code: 'payload_invalid',
          message: 'Limit order was not found or cannot be cancelled from current status.',
          actionHint: 'Verify orderId and ensure it is open/triggered.'
        },
        requestId
      );
    }

    return successResponse({ ok: true, orderId: updated.order_id, status: updated.status }, 200, requestId);
  } catch {
    return internalErrorResponse(requestId);
  }
}
