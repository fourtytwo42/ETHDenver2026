import type { NextRequest } from 'next/server';

import { dbQuery } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

export async function GET(
  req: NextRequest,
  context: { params: Promise<{ agentId: string }> }
) {
  const requestId = getRequestId(req);

  try {
    const { agentId } = await context.params;

    const agent = await dbQuery<{
      agent_id: string;
      agent_name: string;
      description: string | null;
      owner_label: string | null;
      runtime_platform: string;
      public_status: string;
      created_at: string;
      updated_at: string;
      last_activity_at: string | null;
    }>(
      `
      select
        a.agent_id,
        a.agent_name,
        a.description,
        a.owner_label,
        a.runtime_platform,
        a.public_status,
        a.created_at::text,
        a.updated_at::text,
        (
          select max(ev.created_at)::text
          from agent_events ev
          where ev.agent_id = a.agent_id
        ) as last_activity_at
      from agents a
      where a.agent_id = $1
      limit 1
      `,
      [agentId]
    );

    if (agent.rowCount === 0) {
      return errorResponse(
        404,
        {
          code: 'payload_invalid',
          message: 'Agent profile not found.',
          actionHint: 'Verify agentId and retry.'
        },
        requestId
      );
    }

    const wallets = await dbQuery<{
      chain_key: string;
      address: string;
      custody: string;
    }>(
      `
      select chain_key, address, custody
      from agent_wallets
      where agent_id = $1
      order by chain_key asc
      `,
      [agentId]
    );

    const metrics = await dbQuery<{
      window: string;
      pnl_usd: string | null;
      return_pct: string | null;
      volume_usd: string | null;
      trades_count: number;
      followers_count: number;
      created_at: string;
    }>(
      `
      select
        "window" as window,
        pnl_usd::text,
        return_pct::text,
        volume_usd::text,
        trades_count,
        followers_count,
        created_at::text
      from performance_snapshots
      where agent_id = $1
      order by created_at desc
      limit 1
      `,
      [agentId]
    );

    return successResponse(
      {
        ok: true,
        agent: agent.rows[0],
        wallets: wallets.rows,
        latestMetrics: metrics.rows[0] ?? null
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
