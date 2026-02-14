import type { NextRequest } from 'next/server';

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
    const mode = req.nextUrl.searchParams.get('mode') ?? 'all';
    const chain = req.nextUrl.searchParams.get('chain') ?? 'all';
    const status = req.nextUrl.searchParams.get('status') ?? 'all';
    const sort = req.nextUrl.searchParams.get('sort') ?? 'registration';
    const includeDeactivated = parseBoolean(req.nextUrl.searchParams.get('includeDeactivated'), false);
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
        ))
        and ($3 = '' or a.public_status::text = $3)
        and ($4::boolean = true or a.public_status <> 'deactivated')
      `,
      [query, likeQuery, statusFilter, includeDeactivated]
    );

    const rows = await dbQuery<{
      agent_id: string;
      agent_name: string;
      runtime_platform: string;
      public_status: string;
      created_at: string;
      last_activity_at: string | null;
      last_heartbeat_at: string | null;
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
        ) as last_heartbeat_at
      from agents a
      where
        ($1 = ''
        or a.agent_name ilike $2
        or a.agent_id ilike $2
        or exists (
          select 1
          from agent_wallets aw
          where aw.agent_id = a.agent_id
            and aw.address ilike $2
        ))
        and ($5 = '' or a.public_status::text = $5)
        and ($6::boolean = true or a.public_status <> 'deactivated')
      order by ${orderBy}
      limit $3 offset $4
      `,
      [query, likeQuery, pageSize, offset, statusFilter, includeDeactivated]
    );

    return successResponse(
      {
        ok: true,
        query,
        mode,
        chain,
        status,
        sort,
        includeDeactivated,
        page,
        pageSize,
        total: Number(totalRows.rows[0]?.total ?? '0'),
        items: rows.rows
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
