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

type TradeUsageRequest = {
  schemaVersion: 1;
  agentId: string;
  chainKey: string;
  utcDay: string;
  spendUsdDelta: string;
  filledTradesDelta: number;
};

function asNonNegativeNumber(raw: string): number {
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return 0;
  }
  return parsed;
}

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<TradeUsageRequest>('agent-trade-usage-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Trade usage payload does not match schema.',
          actionHint: 'Provide schemaVersion, agentId, chainKey, utcDay, spendUsdDelta, and filledTradesDelta.',
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

    const spendUsdDelta = asNonNegativeNumber(body.spendUsdDelta);
    const filledTradesDelta = Math.max(0, Math.trunc(body.filledTradesDelta));

    const idempotency = await ensureIdempotency(req, 'agent_trade_usage', body.agentId, body, requestId);
    if (!idempotency.ok) {
      return idempotency.response;
    }
    if (idempotency.ctx.replayResponse) {
      return successResponse(idempotency.ctx.replayResponse.body, idempotency.ctx.replayResponse.status, requestId);
    }

    const result = await withTransaction(async (client) => {
      const row = await client.query<{
        daily_spend_usd: string;
        daily_filled_trades: string;
      }>(
        `
        insert into agent_daily_trade_usage (
          usage_id,
          agent_id,
          chain_key,
          utc_day,
          daily_spend_usd,
          daily_filled_trades,
          updated_at
        ) values ($1, $2, $3, $4::date, $5::numeric, $6, now())
        on conflict (agent_id, chain_key, utc_day)
        do update
          set daily_spend_usd = agent_daily_trade_usage.daily_spend_usd + excluded.daily_spend_usd,
              daily_filled_trades = agent_daily_trade_usage.daily_filled_trades + excluded.daily_filled_trades,
              updated_at = now()
        returning daily_spend_usd::text, daily_filled_trades::text
        `,
        [makeId('tdu'), body.agentId, body.chainKey, body.utcDay, String(spendUsdDelta), filledTradesDelta]
      );

      await client.query(
        `
        insert into agent_events (event_id, agent_id, trade_id, event_type, payload, created_at)
        values ($1, $2, null, 'trade_usage_reported', $3::jsonb, now())
        `,
        [
          makeId('evt'),
          body.agentId,
          JSON.stringify({
            chainKey: body.chainKey,
            utcDay: body.utcDay,
            spendUsdDelta: String(spendUsdDelta),
            filledTradesDelta
          })
        ]
      );

      return row.rows[0];
    });

    const responseBody = {
      ok: true,
      agentId: body.agentId,
      chainKey: body.chainKey,
      utcDay: body.utcDay,
      dailySpendUsd: result.daily_spend_usd,
      dailyFilledTrades: Number.parseInt(result.daily_filled_trades, 10)
    };

    await storeIdempotencyResponse(idempotency.ctx, 200, responseBody);
    return successResponse(responseBody, 200, requestId);
  } catch {
    return internalErrorResponse(requestId);
  }
}
