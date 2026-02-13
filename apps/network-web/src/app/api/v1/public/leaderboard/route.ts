import type { NextRequest } from 'next/server';

import { dbQuery } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

function parseBoolean(value: string | null, fallback: boolean): boolean {
  if (value === null || value === '') {
    return fallback;
  }

  if (value === 'true' || value === '1') {
    return true;
  }
  if (value === 'false' || value === '0') {
    return false;
  }

  return fallback;
}

export async function GET(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const window = req.nextUrl.searchParams.get('window') ?? '7d';
    const mode = req.nextUrl.searchParams.get('mode') ?? 'mock';
    const chain = req.nextUrl.searchParams.get('chain') ?? 'all';
    const includeDeactivated = parseBoolean(req.nextUrl.searchParams.get('includeDeactivated'), false);

    if (!['24h', '7d', '30d', 'all'].includes(window)) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Invalid window query value.',
          actionHint: 'Use one of: 24h, 7d, 30d, all.'
        },
        requestId
      );
    }

    if (!['mock', 'real', 'all'].includes(mode)) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Invalid mode query value.',
          actionHint: 'Use one of: mock, real, all.'
        },
        requestId
      );
    }

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
        and ($2::boolean = true or a.public_status <> 'deactivated')
      order by ps.return_pct desc nulls last, ps.volume_usd desc nulls last, a.created_at asc
      limit 100
      `,
      [window, includeDeactivated]
    );

    return successResponse(
      {
        ok: true,
        window,
        mode,
        chain,
        includeDeactivated,
        items: rows.rows
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
