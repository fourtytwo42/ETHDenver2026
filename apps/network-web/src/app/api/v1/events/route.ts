import type { NextRequest } from 'next/server';

import { requireAgentAuth } from '@/lib/agent-auth';
import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { ensureIdempotency, storeIdempotencyResponse } from '@/lib/idempotency';
import { makeId } from '@/lib/ids';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type EventRequest = {
  schemaVersion: number;
  agentId: string;
  tradeId?: string | null;
  eventType: string;
  payload?: Record<string, unknown>;
  createdAt: string;
};

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<EventRequest>('event-ingest-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Event payload does not match schema.',
          actionHint: 'Validate eventType and createdAt with a supported payload structure.',
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

    const idempotency = await ensureIdempotency(req, 'events_ingest', body.agentId, body, requestId);
    if (!idempotency.ok) {
      return idempotency.response;
    }

    if (idempotency.ctx.replayResponse) {
      return successResponse(idempotency.ctx.replayResponse.body, idempotency.ctx.replayResponse.status, requestId);
    }

    await withTransaction(async (client) => {
      await client.query(
        `
        insert into agent_events (event_id, agent_id, trade_id, event_type, payload, created_at)
        values ($1, $2, $3, $4, $5::jsonb, $6::timestamptz)
        `,
        [
          makeId('evt'),
          body.agentId,
          body.tradeId ?? null,
          body.eventType,
          JSON.stringify(body.payload ?? {}),
          body.createdAt
        ]
      );
    });

    const responseBody = {
      ok: true,
      eventType: body.eventType
    };

    await storeIdempotencyResponse(idempotency.ctx, 200, responseBody);
    return successResponse(responseBody, 200, requestId);
  } catch (error) {
    const maybeCode = (error as { code?: string }).code;
    if (maybeCode === '22P02' || maybeCode === '23503') {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Event payload references invalid agent/trade values.',
          actionHint: 'Ensure referenced resources exist before submitting events.',
          details: { databaseCode: maybeCode }
        },
        requestId
      );
    }

    return internalErrorResponse(requestId);
  }
}
