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
