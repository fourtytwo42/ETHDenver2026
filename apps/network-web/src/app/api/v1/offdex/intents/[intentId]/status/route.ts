import type { NextRequest } from 'next/server';

import { authenticateAgentByToken } from '@/lib/agent-auth';
import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { ensureIdempotency, storeIdempotencyResponse } from '@/lib/idempotency';
import { makeId } from '@/lib/ids';
import {
  deriveFundingStatus,
  isAllowedOffdexTransition,
  isOffdexParticipant,
  type OffdexIntentRow
} from '@/lib/offdex-state';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type OffdexStatusUpdateRequest = {
  status: string;
  failureCode?: string;
  failureMessage?: string;
  makerFundTxHash?: string;
  takerFundTxHash?: string;
  settlementTxHash?: string;
  escrowDealId?: string;
  at: string;
};

function actorCanSetStatus(row: OffdexIntentRow, agentId: string, nextStatus: string): boolean {
  if (nextStatus === 'maker_funded') {
    return row.maker_agent_id === agentId;
  }
  if (nextStatus === 'taker_funded') {
    return row.taker_agent_id === agentId;
  }
  return true;
}

export async function POST(
  req: NextRequest,
  context: { params: Promise<{ intentId: string }> }
) {
  const requestId = getRequestId(req);

  try {
    const { intentId } = await context.params;

    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<OffdexStatusUpdateRequest>('offdex-status-update-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Off-DEX status payload does not match schema.',
          actionHint: 'Provide allowed status fields and timestamp.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;
    const auth = authenticateAgentByToken(req, requestId);
    if (!auth.ok) {
      return auth.response;
    }

    const idempotency = await ensureIdempotency(req, 'offdex_status', auth.agentId, { intentId, ...body }, requestId);
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

      const makerFundTxHash = body.makerFundTxHash ?? row.maker_fund_tx_hash;
      const takerFundTxHash = body.takerFundTxHash ?? row.taker_fund_tx_hash;
      let nextStatus = body.status;
      if (nextStatus === 'maker_funded' || nextStatus === 'taker_funded' || nextStatus === 'ready_to_settle') {
        nextStatus = deriveFundingStatus({
          ...row,
          maker_fund_tx_hash: makerFundTxHash ?? null,
          taker_fund_tx_hash: takerFundTxHash ?? null
        });
      }

      if (!actorCanSetStatus(row, auth.agentId, body.status)) {
        return { ok: false as const, kind: 'actor' as const, currentStatus: row.status };
      }
      if (!isAllowedOffdexTransition(row.status, nextStatus)) {
        return { ok: false as const, kind: 'transition' as const, currentStatus: row.status, nextStatus };
      }

      await client.query(
        `
        update offdex_settlement_intents
        set
          status = $1::offdex_settlement_status,
          failure_code = $2,
          failure_message = $3,
          maker_fund_tx_hash = $4,
          taker_fund_tx_hash = $5,
          settlement_tx_hash = coalesce($6, settlement_tx_hash),
          escrow_deal_id = coalesce($7, escrow_deal_id),
          updated_at = now()
        where settlement_intent_id = $8
        `,
        [
          nextStatus,
          body.failureCode ?? null,
          body.failureMessage ?? null,
          makerFundTxHash ?? null,
          takerFundTxHash ?? null,
          body.settlementTxHash ?? null,
          body.escrowDealId ?? null,
          intentId
        ]
      );

      await client.query(
        `
        insert into management_audit_log (
          audit_id, agent_id, management_session_id, action_type, action_status, public_redacted_payload, private_payload, user_agent, created_at
        ) values ($1, $2, null, 'offdex.intent.status', 'accepted', $3::jsonb, $4::jsonb, $5, $6::timestamptz)
        `,
        [
          makeId('aud'),
          auth.agentId,
          JSON.stringify({ settlementIntentId: intentId, status: nextStatus }),
          JSON.stringify({
            makerFundTxHash: makerFundTxHash ?? null,
            takerFundTxHash: takerFundTxHash ?? null,
            settlementTxHash: body.settlementTxHash ?? null,
            escrowDealId: body.escrowDealId ?? null
          }),
          req.headers.get('user-agent'),
          body.at
        ]
      );

      return { ok: true as const, nextStatus };
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
      if (update.kind === 'actor') {
        return errorResponse(
          409,
          {
            code: 'trade_invalid_transition',
            message: 'Agent role cannot apply this funding transition.',
            actionHint: 'Maker sets maker_funded, taker sets taker_funded.',
            details: { currentStatus: update.currentStatus }
          },
          requestId
        );
      }
      return errorResponse(
        409,
        {
          code: 'trade_invalid_transition',
          message: 'Off-DEX status transition is not allowed.',
          actionHint: 'Refresh current status and retry with an allowed transition.',
          details: { currentStatus: update.currentStatus, nextStatus: update.nextStatus }
        },
        requestId
      );
    }

    const responseBody = {
      ok: true,
      settlementIntentId: intentId,
      status: update.nextStatus
    };
    await storeIdempotencyResponse(idempotency.ctx, 200, responseBody);
    return successResponse(responseBody, 200, requestId);
  } catch {
    return internalErrorResponse(requestId);
  }
}
