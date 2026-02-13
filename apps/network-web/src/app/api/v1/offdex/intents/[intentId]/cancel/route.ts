import type { NextRequest } from 'next/server';

import { authenticateAgentByToken } from '@/lib/agent-auth';
import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { ensureIdempotency, storeIdempotencyResponse } from '@/lib/idempotency';
import { makeId } from '@/lib/ids';
import { isOffdexParticipant, type OffdexIntentRow } from '@/lib/offdex-state';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

const CANCELLABLE_STATUSES = new Set(['proposed', 'accepted', 'maker_funded', 'taker_funded', 'ready_to_settle']);

export async function POST(
  req: NextRequest,
  context: { params: Promise<{ intentId: string }> }
) {
  const requestId = getRequestId(req);

  try {
    const auth = authenticateAgentByToken(req, requestId);
    if (!auth.ok) {
      return auth.response;
    }

    const { intentId } = await context.params;
    const idempotency = await ensureIdempotency(req, 'offdex_cancel', auth.agentId, { intentId }, requestId);
    if (!idempotency.ok) {
      return idempotency.response;
    }
    if (idempotency.ctx.replayResponse) {
      return successResponse(idempotency.ctx.replayResponse.body, idempotency.ctx.replayResponse.status, requestId);
    }

    const update = await withTransaction(async (client) => {
      await client.query(
        `
        update offdex_settlement_intents
        set status = 'expired'::offdex_settlement_status, updated_at = now()
        where settlement_intent_id = $1
          and status not in ('settled', 'cancelled', 'expired', 'failed')
          and expires_at <= now()
        `,
        [intentId]
      );

      const intent = await client.query<OffdexIntentRow>(
        `
        select status, maker_agent_id, taker_agent_id, expires_at::text, maker_fund_tx_hash, taker_fund_tx_hash
        from offdex_settlement_intents
        where settlement_intent_id = $1
        limit 1
        `,
        [intentId]
      );
      if (intent.rowCount === 0) {
        return { ok: false as const, kind: 'missing' as const };
      }
      const row = intent.rows[0];
      if (!isOffdexParticipant(row, auth.agentId)) {
        return { ok: false as const, kind: 'auth' as const };
      }
      if (!CANCELLABLE_STATUSES.has(row.status)) {
        return { ok: false as const, kind: 'transition' as const, currentStatus: row.status };
      }

      await client.query(
        `
        update offdex_settlement_intents
        set status = 'cancelled'::offdex_settlement_status, updated_at = now()
        where settlement_intent_id = $1
        `,
        [intentId]
      );

      await client.query(
        `
        insert into management_audit_log (
          audit_id, agent_id, management_session_id, action_type, action_status, public_redacted_payload, private_payload, user_agent, created_at
        ) values ($1, $2, null, 'offdex.intent.cancel', 'accepted', $3::jsonb, $4::jsonb, $5, now())
        `,
        [
          makeId('aud'),
          auth.agentId,
          JSON.stringify({ settlementIntentId: intentId, status: 'cancelled' }),
          JSON.stringify({}),
          req.headers.get('user-agent')
        ]
      );

      return { ok: true as const };
    });

    if (!update.ok) {
      if (update.kind === 'missing') {
        return errorResponse(
          404,
          {
            code: 'payload_invalid',
            message: 'Off-DEX intent was not found.',
            actionHint: 'Verify intentId and retry.'
          },
          requestId
        );
      }
      if (update.kind === 'auth') {
        return errorResponse(
          401,
          {
            code: 'auth_invalid',
            message: 'Authenticated agent is not a participant in this off-DEX intent.',
            actionHint: 'Use bearer token for maker or taker agent.'
          },
          requestId
        );
      }
      return errorResponse(
        409,
        {
          code: 'trade_invalid_transition',
          message: 'Off-DEX intent cannot be cancelled from current state.',
          actionHint: 'Cancel only intents that are not settling or terminal.',
          details: { currentStatus: update.currentStatus }
        },
        requestId
      );
    }

    const responseBody = { ok: true, settlementIntentId: intentId, status: 'cancelled' };
    await storeIdempotencyResponse(idempotency.ctx, 200, responseBody);
    return successResponse(responseBody, 200, requestId);
  } catch {
    return internalErrorResponse(requestId);
  }
}
