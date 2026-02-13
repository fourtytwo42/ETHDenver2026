import type { NextRequest } from 'next/server';

import { authenticateAgentByToken } from '@/lib/agent-auth';
import { dbQuery, withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseIntQuery } from '@/lib/http';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

export async function GET(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const auth = authenticateAgentByToken(req, requestId);
    if (!auth.ok) {
      return auth.response;
    }

    const chainKey = req.nextUrl.searchParams.get('chainKey')?.trim();
    if (!chainKey) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'chainKey query parameter is required.',
          actionHint: 'Provide ?chainKey=<chain-key>.'
        },
        requestId
      );
    }

    const limit = parseIntQuery(req.nextUrl.searchParams.get('limit'), 100, 1, 200);

    await withTransaction(async (client) => {
      await client.query(
        `
        update limit_orders
        set status = 'expired', updated_at = now()
        where agent_id = $1
          and chain_key = $2
          and status = 'open'
          and expires_at is not null
          and expires_at <= now()
        `,
        [auth.agentId, chainKey]
      );
    });

    const orders = await dbQuery<{
      order_id: string;
      agent_id: string;
      chain_key: string;
      mode: 'mock' | 'real';
      side: 'buy' | 'sell';
      token_in: string;
      token_out: string;
      amount_in: string;
      limit_price: string;
      slippage_bps: number;
      status: string;
      expires_at: string | null;
      updated_at: string;
      created_at: string;
    }>(
      `
      select
        order_id,
        agent_id,
        chain_key,
        mode,
        side,
        token_in,
        token_out,
        amount_in::text,
        limit_price::text,
        slippage_bps,
        status::text,
        expires_at::text,
        updated_at::text,
        created_at::text
      from limit_orders
      where agent_id = $1
        and chain_key = $2
        and status = 'open'
        and (expires_at is null or expires_at > now())
      order by created_at asc
      limit $3
      `,
      [auth.agentId, chainKey, limit]
    );

    return successResponse(
      {
        ok: true,
        agentId: auth.agentId,
        chainKey,
        limit,
        items: orders.rows.map((row) => ({
          orderId: row.order_id,
          agentId: row.agent_id,
          chainKey: row.chain_key,
          mode: row.mode,
          side: row.side,
          tokenIn: row.token_in,
          tokenOut: row.token_out,
          amountIn: row.amount_in,
          limitPrice: row.limit_price,
          slippageBps: row.slippage_bps,
          status: row.status,
          expiresAt: row.expires_at,
          updatedAt: row.updated_at,
          createdAt: row.created_at
        }))
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
