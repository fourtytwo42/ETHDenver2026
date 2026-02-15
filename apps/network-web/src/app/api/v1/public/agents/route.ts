import type { NextRequest } from 'next/server';

import { getChainConfig } from '@/lib/chains';
import { dbQuery } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseIntQuery } from '@/lib/http';
import { PUBLIC_STATUSES, isPublicStatus } from '@/lib/public-types';
import { enforcePublicReadRateLimit } from '@/lib/rate-limit';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

const SORT_TO_ORDER_BY: Record<string, string> = {
  registration: 'a.created_at desc',
  agent_name: 'a.agent_name asc',
  last_activity: 'last_activity_at desc nulls last'
};

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
    const rateLimited = await enforcePublicReadRateLimit(req, requestId);
    if (!rateLimited.ok) {
      return rateLimited.response;
    }

    const query = (req.nextUrl.searchParams.get('query') ?? '').trim();
    const requestedMode = req.nextUrl.searchParams.get('mode') ?? 'all';
    const mode: 'real' = 'real';
    const chain = req.nextUrl.searchParams.get('chain') ?? 'all';
    if (chain !== 'all' && !getChainConfig(chain)) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Invalid chain query value.',
          actionHint: 'Use one of: all, base_sepolia, hardhat_local.'
        },
        requestId
      );
    }
    const status = req.nextUrl.searchParams.get('status') ?? 'all';
    const sort = req.nextUrl.searchParams.get('sort') ?? 'registration';
    const includeDeactivated = parseBoolean(req.nextUrl.searchParams.get('includeDeactivated'), false);
    const includeMetrics = parseBoolean(req.nextUrl.searchParams.get('includeMetrics'), false);
    const page = parseIntQuery(req.nextUrl.searchParams.get('page'), 1, 1, 10000);
    const pageSize = parseIntQuery(req.nextUrl.searchParams.get('pageSize'), 20, 1, 100);
    const offset = (page - 1) * pageSize;
    const likeQuery = `%${query}%`;

    const orderBy = SORT_TO_ORDER_BY[sort];
    if (!orderBy) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Invalid sort query value.',
          actionHint: `Use one of: ${Object.keys(SORT_TO_ORDER_BY).join(', ')}.`
        },
        requestId
      );
    }

    if (status !== 'all' && !isPublicStatus(status)) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Invalid status query value.',
          actionHint: `Use one of: all, ${PUBLIC_STATUSES.join(', ')}.`
        },
        requestId
      );
    }

    const statusFilter = status === 'all' ? '' : status;

    const totalRows = await dbQuery<{ total: string }>(
      `
      select count(*)::text as total
      from agents a
      where
        ($1 = '' or a.agent_name ilike $2 or a.agent_id ilike $2 or exists (
          select 1
          from agent_wallets aw
          where aw.agent_id = a.agent_id
            and aw.address ilike $2
            and ($5 = 'all' or aw.chain_key = $5)
        ))
        and ($3 = '' or a.public_status::text = $3)
        and ($4::boolean = true or a.public_status <> 'deactivated')
        and ($5 = 'all' or exists (
          select 1 from agent_wallets aw2 where aw2.agent_id = a.agent_id and aw2.chain_key = $5
        ))
      `,
      [query, likeQuery, statusFilter, includeDeactivated, chain]
    );

    const rows = await dbQuery<{
      agent_id: string;
      agent_name: string;
      runtime_platform: string;
      public_status: string;
      created_at: string;
      last_activity_at: string | null;
      last_heartbeat_at: string | null;
      wallet_chain_key: string | null;
      wallet_address: string | null;
      latest_pnl_usd: string | null;
      latest_return_pct: string | null;
      latest_volume_usd: string | null;
      latest_trades_count: number | null;
      latest_followers_count: number | null;
      latest_metrics_as_of: string | null;
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
        ,
        (
          select max(ev.created_at)::text
          from agent_events ev
          where ev.agent_id = a.agent_id
            and ev.event_type = 'heartbeat'
        ) as last_heartbeat_at,
        wallet.chain_key as wallet_chain_key,
        wallet.address as wallet_address,
        metrics.pnl_usd as latest_pnl_usd,
        metrics.return_pct as latest_return_pct,
        metrics.volume_usd as latest_volume_usd,
        metrics.trades_count as latest_trades_count,
        metrics.followers_count as latest_followers_count,
        metrics.as_of as latest_metrics_as_of
      from agents a
      left join lateral (
        select aw.chain_key, aw.address
        from agent_wallets aw
        where aw.agent_id = a.agent_id
          and ($7 = 'all' or aw.chain_key = $7)
        order by case when aw.chain_key = $7 then 0 else 1 end, aw.chain_key asc
        limit 1
      ) wallet on true
      left join lateral (
        select
          ps.pnl_usd::text as pnl_usd,
          ps.return_pct::text as return_pct,
          ps.volume_usd::text as volume_usd,
          ps.trades_count,
          ps.followers_count,
          ps.created_at::text as as_of
        from performance_snapshots ps
        where ps.agent_id = a.agent_id
          and ps.mode = 'real'
          and ps.chain_key = 'all'
          and ps."window" = '7d'::performance_window
        order by ps.created_at desc
        limit 1
      ) metrics on true
      where
        ($1 = ''
        or a.agent_name ilike $2
        or a.agent_id ilike $2
        or exists (
          select 1
          from agent_wallets aw
          where aw.agent_id = a.agent_id
            and aw.address ilike $2
            and ($7 = 'all' or aw.chain_key = $7)
        ))
        and ($5 = '' or a.public_status::text = $5)
        and ($6::boolean = true or a.public_status <> 'deactivated')
        and ($7 = 'all' or exists (
          select 1 from agent_wallets aw2 where aw2.agent_id = a.agent_id and aw2.chain_key = $7
        ))
      order by ${orderBy}
      limit $3 offset $4
      `,
      [query, likeQuery, pageSize, offset, statusFilter, includeDeactivated, chain]
    );

    return successResponse(
      {
        ok: true,
        query,
        mode,
        requestedMode,
        chain,
        status,
        sort,
        includeDeactivated,
        includeMetrics,
        page,
        pageSize,
        total: Number(totalRows.rows[0]?.total ?? '0'),
        items: rows.rows.map((row) => ({
          agent_id: row.agent_id,
          agent_name: row.agent_name,
          runtime_platform: row.runtime_platform,
          public_status: row.public_status,
          created_at: row.created_at,
          last_activity_at: row.last_activity_at,
          last_heartbeat_at: row.last_heartbeat_at,
          wallet: row.wallet_address
            ? {
                chain_key: row.wallet_chain_key ?? (chain === 'all' ? 'base_sepolia' : chain),
                address: row.wallet_address
              }
            : null,
          latestMetrics: includeMetrics
            ? {
                pnl_usd: row.latest_pnl_usd,
                return_pct: row.latest_return_pct,
                volume_usd: row.latest_volume_usd,
                trades_count: row.latest_trades_count,
                followers_count: row.latest_followers_count,
                as_of: row.latest_metrics_as_of
              }
            : null
        }))
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
