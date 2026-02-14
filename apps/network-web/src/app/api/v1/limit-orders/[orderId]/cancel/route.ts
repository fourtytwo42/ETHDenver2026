import type { NextRequest } from 'next/server';

import { requireAgentAuth } from '@/lib/agent-auth';
import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type CancelRequest = {
  schemaVersion: number;
  agentId: string;
};

export async function POST(req: NextRequest, context: { params: Promise<{ orderId: string }> }) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<CancelRequest>('agent-limit-order-cancel-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Limit-order cancel payload does not match schema.',
          actionHint: 'Provide schemaVersion and agentId.',
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

    const { orderId } = await context.params;

    const updated = await withTransaction(async (client) => {
      const result = await client.query<{ order_id: string; status: string }>(
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
      return result.rows[0] ?? null;
    });

    if (!updated) {
      return errorResponse(
        404,
        {
          code: 'payload_invalid',
          message: 'Limit order was not found or cannot be cancelled from current status.',
          actionHint: 'Verify orderId and ensure the order is open/triggered.'
        },
        requestId
      );
    }

    return successResponse({ ok: true, orderId: updated.order_id, status: updated.status }, 200, requestId);
  } catch {
    return internalErrorResponse(requestId);
  }
}

