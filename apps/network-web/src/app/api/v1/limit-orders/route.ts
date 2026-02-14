import type { NextRequest } from 'next/server';

import { authenticateAgentByToken, requireAgentAuth } from '@/lib/agent-auth';
import { dbQuery, withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseIntQuery, parseJsonBody } from '@/lib/http';
import { makeId } from '@/lib/ids';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type CreateLimitOrderRequest = {
  schemaVersion: number;
  agentId: string;
  chainKey: string;
  mode: 'mock' | 'real';
  side: 'buy' | 'sell';
  tokenIn: string;
  tokenOut: string;
  amountIn: string;
  limitPrice: string;
  slippageBps: number;
  expiresAt?: string;
};

const MAX_OPEN_PER_CHAIN = 10;

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<CreateLimitOrderRequest>('agent-limit-order-create-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Limit-order create payload does not match schema.',
          actionHint: 'Provide schemaVersion, agentId, chainKey, tokenIn, tokenOut, amountIn, limitPrice, and slippageBps.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;
    const auth = requireAgentAuth(req, body.agentId, requestId);
    if (!auth.ok) {
      return auth.response;
    }

    const orderId = makeId('lmt');

    const createResult = await withTransaction(async (client) => {
      const owner = await client.query<{ agent_id: string }>(
        `
        select agent_id
        from agents
        where agent_id = $1
        for update
        `,
        [body.agentId]
      );
      if (owner.rowCount === 0) {
        return { kind: 'auth_invalid' as const };
      }

      const counts = await client.query<{ total: string }>(
        `
        select count(*)::text as total
        from limit_orders
        where agent_id = $1
          and chain_key = $2
          and status in ('open', 'triggered')
        `,
        [body.agentId, body.chainKey]
      );
      const total = Number.parseInt(counts.rows[0]?.total ?? '0', 10);
      if (total >= MAX_OPEN_PER_CHAIN) {
        return { kind: 'limit_reached' as const, total };
      }

      await client.query(
        `
        insert into limit_orders (
          order_id, agent_id, chain_key, mode, side, token_in, token_out,
          amount_in, limit_price, slippage_bps, status, expires_at, trigger_source, created_at, updated_at
        ) values (
          $1, $2, $3, $4::policy_mode, $5::limit_order_side, $6, $7,
          $8::numeric, $9::numeric, $10, 'open', $11, 'agent_local', now(), now()
        )
        `,
        [orderId, body.agentId, body.chainKey, body.mode, body.side, body.tokenIn, body.tokenOut, body.amountIn, body.limitPrice, body.slippageBps, body.expiresAt ?? null]
      );

      return { kind: 'ok' as const };
    });

    if (createResult.kind === 'auth_invalid') {
      return errorResponse(
        401,
        {
          code: 'auth_invalid',
          message: 'Authenticated agent is not registered.',
          actionHint: 'Register agent before creating limit orders.'
        },
        requestId
      );
    }

    if (createResult.kind === 'limit_reached') {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: `Open limit-order cap reached (max ${MAX_OPEN_PER_CHAIN} per chain).`,
          actionHint: 'Cancel one or more open orders, then retry create.',
          details: {
            chainKey: body.chainKey,
            openOrders: createResult.total,
            cap: MAX_OPEN_PER_CHAIN
          }
        },
        requestId
      );
    }

    return successResponse({ ok: true, orderId, status: 'open' }, 200, requestId);
  } catch {
    return internalErrorResponse(requestId);
  }
}

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

    const status = req.nextUrl.searchParams.get('status')?.trim();
    const limit = parseIntQuery(req.nextUrl.searchParams.get('limit'), 50, 1, 200);

    const params: unknown[] = [auth.agentId, chainKey];
    let statusFilter = '';
    if (status) {
      params.push(status);
      statusFilter = `and status = $${params.length}::limit_order_status`;
    }
    params.push(limit);

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
      cancelled_at: string | null;
      trigger_source: string;
      created_at: string;
      updated_at: string;
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
        cancelled_at::text,
        trigger_source::text,
        created_at::text,
        updated_at::text
      from limit_orders
      where agent_id = $1
        and chain_key = $2
        ${statusFilter}
      order by created_at desc
      limit $${params.length}
      `,
      params
    );

    return successResponse(
      {
        ok: true,
        agentId: auth.agentId,
        chainKey,
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
          cancelledAt: row.cancelled_at,
          triggerSource: row.trigger_source,
          createdAt: row.created_at,
          updatedAt: row.updated_at
        }))
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
