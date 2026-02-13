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

type TradeProposedRequest = {
  schemaVersion: number;
  agentId: string;
  chainKey: string;
  mode: 'mock' | 'real';
  tokenIn: string;
  tokenOut: string;
  amountIn: string;
  slippageBps: number;
  amountOut?: string | null;
  priceImpactBps?: number | null;
  reason?: string | null;
};

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<TradeProposedRequest>('trade-proposed-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Trade proposed payload does not match schema.',
          actionHint: 'Verify required fields, numeric formats, and mode values.',
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

    const idempotency = await ensureIdempotency(req, 'trade_proposed', body.agentId, body, requestId);
    if (!idempotency.ok) {
      return idempotency.response;
    }

    if (idempotency.ctx.replayResponse) {
      return successResponse(idempotency.ctx.replayResponse.body, idempotency.ctx.replayResponse.status, requestId);
    }

    const tradeId = makeId('trd');

    const inserted = await withTransaction(async (client) => {
      const agent = await client.query('select agent_id from agents where agent_id = $1', [body.agentId]);
      if (agent.rowCount === 0) {
        return { found: false as const };
      }

      await client.query(
        `
        insert into trades (
          trade_id, agent_id, chain_key, is_mock, status,
          token_in, token_out, pair, amount_in, amount_out,
          price_impact_bps, slippage_bps, reason, created_at, updated_at
        )
        values (
          $1, $2, $3, $4, 'proposed',
          $5, $6, $7, $8, $9,
          $10, $11, $12, now(), now()
        )
        `,
        [
          tradeId,
          body.agentId,
          body.chainKey,
          body.mode === 'mock',
          body.tokenIn,
          body.tokenOut,
          `${body.tokenIn}/${body.tokenOut}`,
          body.amountIn,
          body.amountOut ?? null,
          body.priceImpactBps ?? null,
          body.slippageBps,
          body.reason ?? null
        ]
      );

      await client.query(
        `
        insert into agent_events (event_id, agent_id, trade_id, event_type, payload, created_at)
        values ($1, $2, $3, 'trade_proposed', $4::jsonb, now())
        `,
        [
          makeId('evt'),
          body.agentId,
          tradeId,
          JSON.stringify({
            chainKey: body.chainKey,
            mode: body.mode,
            tokenIn: body.tokenIn,
            tokenOut: body.tokenOut,
            amountIn: body.amountIn,
            slippageBps: body.slippageBps
          })
        ]
      );

      return { found: true as const };
    });

    if (!inserted.found) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Trade proposal rejected because agent is not registered.',
          actionHint: 'Register agent before proposing trades.'
        },
        requestId
      );
    }

    const responseBody = {
      ok: true,
      tradeId,
      status: 'proposed'
    };

    await storeIdempotencyResponse(idempotency.ctx, 200, responseBody);
    return successResponse(responseBody, 200, requestId);
  } catch {
    return internalErrorResponse(requestId);
  }
}
