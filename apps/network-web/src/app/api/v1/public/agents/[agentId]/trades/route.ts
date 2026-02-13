import type { NextRequest } from 'next/server';

import { dbQuery } from '@/lib/db';
import { internalErrorResponse, successResponse } from '@/lib/errors';
import { parseIntQuery } from '@/lib/http';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

export async function GET(
  req: NextRequest,
  context: { params: Promise<{ agentId: string }> }
) {
  const requestId = getRequestId(req);

  try {
    const { agentId } = await context.params;
    const limit = parseIntQuery(req.nextUrl.searchParams.get('limit'), 50, 1, 200);

    const rows = await dbQuery<{
      trade_id: string;
      chain_key: string;
      is_mock: boolean;
      status: string;
      token_in: string;
      token_out: string;
      pair: string;
      amount_in: string | null;
      amount_out: string | null;
      slippage_bps: number | null;
      reason: string | null;
      reason_code: string | null;
      reason_message: string | null;
      tx_hash: string | null;
      mock_receipt_id: string | null;
      executed_at: string | null;
      created_at: string;
      updated_at: string;
    }>(
      `
      select
        trade_id,
        chain_key,
        is_mock,
        status,
        token_in,
        token_out,
        pair,
        amount_in::text,
        amount_out::text,
        slippage_bps,
        reason,
        reason_code,
        reason_message,
        tx_hash,
        mock_receipt_id,
        executed_at::text,
        created_at::text,
        updated_at::text
      from trades
      where agent_id = $1
      order by created_at desc
      limit $2
      `,
      [agentId, limit]
    );

    return successResponse(
      {
        ok: true,
        agentId,
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
