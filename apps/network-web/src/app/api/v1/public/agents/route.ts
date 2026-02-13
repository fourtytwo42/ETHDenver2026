import type { NextRequest } from 'next/server';

import { dbQuery } from '@/lib/db';
import { internalErrorResponse, successResponse } from '@/lib/errors';
import { parseIntQuery } from '@/lib/http';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

export async function GET(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const query = (req.nextUrl.searchParams.get('query') ?? '').trim();
    const mode = req.nextUrl.searchParams.get('mode') ?? 'all';
    const chain = req.nextUrl.searchParams.get('chain') ?? 'all';
    const page = parseIntQuery(req.nextUrl.searchParams.get('page'), 1, 1, 10000);
    const pageSize = 20;
    const offset = (page - 1) * pageSize;
    const likeQuery = `%${query}%`;

    const rows = await dbQuery<{
      agent_id: string;
      agent_name: string;
      runtime_platform: string;
      public_status: string;
      created_at: string;
      last_activity_at: string | null;
    }>(
      `
      select
        a.agent_id,
        a.agent_name,
        a.runtime_platform,
        a.public_status,
        a.created_at::text,
        (
          select max(ev.created_at)::text
          from agent_events ev
          where ev.agent_id = a.agent_id
        ) as last_activity_at
      from agents a
      where
        $1 = ''
        or a.agent_name ilike $2
        or a.agent_id ilike $2
        or exists (
          select 1
          from agent_wallets aw
          where aw.agent_id = a.agent_id
            and aw.address ilike $2
        )
      order by a.created_at desc
      limit $3 offset $4
      `,
      [query, likeQuery, pageSize, offset]
    );

    return successResponse(
      {
        ok: true,
        query,
        mode,
        chain,
        page,
        pageSize,
        items: rows.rows
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
