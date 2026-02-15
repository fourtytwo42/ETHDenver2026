import type { NextRequest } from 'next/server';

import { authenticateAgentByToken } from '@/lib/agent-auth';
import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { makeId } from '@/lib/ids';
import { getRequestId } from '@/lib/request-id';
import { requireAgentChainEnabled } from '@/lib/agent-chain-policy';
import { evaluateTradeCaps } from '@/lib/trade-caps';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type StatusUpdateRequest = {
  status: 'triggered' | 'filled' | 'failed' | 'expired';
  triggerPrice?: string;
  triggerAt?: string;
  reasonCode?: string;
  reasonMessage?: string;
  txHash?: string;
  mockReceiptId?: string;
};

export async function POST(req: NextRequest, context: { params: Promise<{ orderId: string }> }) {
  const requestId = getRequestId(req);

  try {
    const auth = authenticateAgentByToken(req, requestId);
    if (!auth.ok) {
      return auth.response;
    }

    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<StatusUpdateRequest>('limit-order-status-update-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Limit-order status payload does not match schema.',
          actionHint: 'Provide valid status and optional execution details.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;
    const { orderId } = await context.params;

    const result = await withTransaction(async (client) => {
      const order = await client.query<{
        order_id: string;
        agent_id: string;
        chain_key: string;
        mode: 'mock' | 'real';
        token_in: string;
        token_out: string;
        amount_in: string;
        status: string;
      }>(
        `
        select order_id, agent_id, chain_key, mode, token_in, token_out, amount_in::text, status::text
        from limit_orders
        where order_id = $1
        limit 1
        `,
        [orderId]
      );

      if (order.rowCount === 0) {
        return { kind: 'missing' as const };
      }

      const row = order.rows[0];
      if (row.agent_id !== auth.agentId) {
        return { kind: 'forbidden' as const };
      }

      if (body.status === 'triggered' || body.status === 'filled') {
        const chainGate = await requireAgentChainEnabled(client, { agentId: row.agent_id, chainKey: row.chain_key });
        if (!chainGate.ok) {
          return { kind: 'blocked' as const, violation: chainGate.violation };
        }
      }

      if (body.status === 'filled') {
        const capCheck = await evaluateTradeCaps(client, {
          agentId: row.agent_id,
          chainKey: row.chain_key,
          projectedSpendUsd: row.amount_in,
          projectedFilledTrades: 1
        });
        if (!capCheck.ok) {
          return { kind: 'blocked' as const, violation: capCheck.violation };
        }
      }

      await client.query(
        `
        update limit_orders
        set status = $2::limit_order_status,
            updated_at = now(),
            trigger_source = 'agent_local'
        where order_id = $1
        `,
        [orderId, body.status]
      );

      const attemptId = makeId('lat');
      await client.query(
        `
        insert into limit_order_attempts (
          attempt_id, order_id, trigger_price, trigger_at, execution_status,
          reason_code, reason_message, tx_hash, mock_receipt_id, created_at
        ) values ($1, $2, $3, $4, $5::limit_order_execution_status, $6, $7, $8, $9, now())
        `,
        [
          attemptId,
          orderId,
          body.triggerPrice ?? null,
          body.triggerAt ?? new Date().toISOString(),
          body.status === 'filled' ? 'filled' : body.status === 'triggered' ? 'executing' : 'failed',
          body.reasonCode ?? null,
          body.reasonMessage ?? null,
          body.txHash ?? null,
          body.mockReceiptId ?? null
        ]
      );

      if (body.status === 'filled') {
        const tradeId = makeId('trd');
        await client.query(
          `
          insert into trades (
            trade_id, agent_id, chain_key, is_mock, status,
            token_in, token_out, pair, amount_in,
            slippage_bps, tx_hash, mock_receipt_id,
            reason, created_at, updated_at, executed_at
          ) values (
            $1, $2, $3, $4, 'filled',
            $5, $6, $7, $8,
            null, $9, $10,
            'limit_order_fill', now(), now(), now()
          )
          `,
          [
            tradeId,
            row.agent_id,
            row.chain_key,
            row.mode === 'mock',
            row.token_in,
            row.token_out,
            `${row.token_in}/${row.token_out}`,
            row.amount_in,
            body.txHash ?? null,
            body.mockReceiptId ?? null
          ]
        );

        await client.query(`update limit_order_attempts set trade_id = $2 where attempt_id = $1`, [attemptId, tradeId]);

        await client.query(
          `
          insert into agent_events (event_id, agent_id, trade_id, event_type, payload, created_at)
          values ($1, $2, $3, 'trade_filled', $4::jsonb, now())
          `,
          [
            makeId('evt'),
            row.agent_id,
            tradeId,
            JSON.stringify({ orderId, triggerPrice: body.triggerPrice ?? null, txHash: body.txHash ?? null })
          ]
        );
      }

      return { kind: 'ok' as const };
    });

    if (result.kind === 'missing') {
      return errorResponse(
        404,
        {
          code: 'payload_invalid',
          message: 'Limit order was not found.',
          actionHint: 'Verify orderId and retry.'
        },
        requestId
      );
    }

    if (result.kind === 'forbidden') {
      return errorResponse(
        401,
        {
          code: 'auth_invalid',
          message: 'Agent is not authorized to update this order.',
          actionHint: 'Use matching agent API key for the order owner.'
        },
        requestId
      );
    }

    if (result.kind === 'blocked') {
      return errorResponse(
        400,
        {
          code: result.violation.code,
          message: result.violation.message,
          actionHint: result.violation.actionHint,
          details: result.violation.details
        },
        requestId
      );
    }

    return successResponse({ ok: true, orderId, status: body.status }, 200, requestId);
  } catch {
    return internalErrorResponse(requestId);
  }
}
