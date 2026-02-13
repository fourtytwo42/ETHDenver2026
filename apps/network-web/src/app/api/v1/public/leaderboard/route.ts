import type { NextRequest } from 'next/server';

import { dbQuery } from '@/lib/db';
import { internalErrorResponse, successResponse } from '@/lib/errors';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

export async function GET(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const window = req.nextUrl.searchParams.get('window') ?? '7d';
    const mode = req.nextUrl.searchParams.get('mode') ?? 'mock';
    const chain = req.nextUrl.searchParams.get('chain') ?? 'all';

    const rows = await dbQuery<{
      agent_id: string;
      agent_name: string;
      public_status: string;
      pnl_usd: string | null;
      return_pct: string | null;
      volume_usd: string | null;
      trades_count: number;
      followers_count: number;
      snapshot_at: string;
    }>(
      `
      select
        ps.agent_id,
        a.agent_name,
        a.public_status,
        ps.pnl_usd::text,
        ps.return_pct::text,
        ps.volume_usd::text,
        ps.trades_count,
        ps.followers_count,
        ps.created_at::text as snapshot_at
      from performance_snapshots ps
      inner join agents a on a.agent_id = ps.agent_id
      where ps."window" = $1
      order by ps.return_pct desc nulls last, ps.volume_usd desc nulls last, a.created_at asc
      limit 100
      `,
      [window]
    );

    return successResponse(
      {
        ok: true,
        window,
        mode,
        chain,
        items: rows.rows
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
