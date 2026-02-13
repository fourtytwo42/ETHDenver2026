import type { NextRequest } from 'next/server';

import { dbQuery } from '@/lib/db';
import { internalErrorResponse, successResponse } from '@/lib/errors';
import { parseIntQuery } from '@/lib/http';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

export async function GET(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const limit = parseIntQuery(req.nextUrl.searchParams.get('limit'), 100, 1, 500);

    const rows = await dbQuery<{
      event_id: string;
      agent_id: string;
      agent_name: string;
      trade_id: string | null;
      event_type: string;
      payload: Record<string, unknown>;
      created_at: string;
    }>(
      `
      select
        ev.event_id,
        ev.agent_id,
        a.agent_name,
        ev.trade_id,
        ev.event_type,
        ev.payload,
        ev.created_at::text
      from agent_events ev
      inner join agents a on a.agent_id = ev.agent_id
      order by ev.created_at desc
      limit $1
      `,
      [limit]
    );

    const offdex = await dbQuery<{
      settlement_intent_id: string;
      maker_agent_id: string;
      taker_agent_id: string | null;
      status: string;
      settlement_tx_hash: string | null;
      maker_fund_tx_hash: string | null;
      taker_fund_tx_hash: string | null;
      updated_at: string;
    }>(
      `
      select
        settlement_intent_id,
        maker_agent_id,
        taker_agent_id,
        status,
        settlement_tx_hash,
        maker_fund_tx_hash,
        taker_fund_tx_hash,
        updated_at::text
      from offdex_settlement_intents
      order by updated_at desc
      limit $1
      `,
      [limit]
    );

    const synthetic = offdex.rows.map((row) => ({
      event_id: `offdex_${row.settlement_intent_id}_${row.status}`,
      agent_id: row.maker_agent_id,
      agent_name: 'offdex',
      trade_id: null,
      event_type: `offdex_${row.status}`,
      payload: {
        settlementIntentId: row.settlement_intent_id,
        role: 'maker',
        settlementTxHash: row.settlement_tx_hash,
        makerFundTxHash: row.maker_fund_tx_hash,
        takerFundTxHash: row.taker_fund_tx_hash
      },
      created_at: row.updated_at
    }));

    const combined = [...rows.rows, ...synthetic]
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
      .slice(0, limit);

    return successResponse(
      {
        ok: true,
        limit,
        items: combined
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
