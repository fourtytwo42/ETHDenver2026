import type { NextRequest } from 'next/server';

import { dbQuery } from '@/lib/db';
import { internalErrorResponse, successResponse } from '@/lib/errors';
import { parseIntQuery } from '@/lib/http';
import { enforcePublicReadRateLimit } from '@/lib/rate-limit';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

export async function GET(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const rateLimited = await enforcePublicReadRateLimit(req, requestId);
    if (!rateLimited.ok) {
      return rateLimited.response;
    }

    const limit = parseIntQuery(req.nextUrl.searchParams.get('limit'), 100, 1, 500);

    const rows = await dbQuery<{
      event_id: string;
      agent_id: string;
      agent_name: string;
      trade_id: string | null;
      event_type: string;
      payload: Record<string, unknown>;
      chain_key: string;
      pair: string | null;
      token_in: string | null;
      token_out: string | null;
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
        coalesce(t.chain_key, nullif(ev.payload->>'chainKey', ''), 'base_sepolia') as chain_key,
        coalesce(t.pair, nullif(ev.payload->>'pair', '')) as pair,
        coalesce(t.token_in, nullif(ev.payload->>'tokenIn', '')) as token_in,
        coalesce(t.token_out, nullif(ev.payload->>'tokenOut', '')) as token_out,
        ev.created_at::text
      from agent_events ev
      inner join agents a on a.agent_id = ev.agent_id
      left join trades t on t.trade_id = ev.trade_id
      where ev.event_type::text like 'trade_%'
      order by ev.created_at desc
      limit $1
      `,
      [limit]
    );

    return successResponse(
      {
        ok: true,
        limit,
        items: rows.rows
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
