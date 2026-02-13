import type { NextRequest } from 'next/server';

import { authenticateAgentByToken } from '@/lib/agent-auth';
import { dbQuery } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

const RETRY_WINDOW_SECONDS = 600;
const MAX_RETRIES = 3;
const RETRYABLE_REASON_CODES = new Set(['rpc_unavailable', 'verification_timeout', 'slippage_exceeded']);

export async function GET(
  req: NextRequest,
  context: { params: Promise<{ tradeId: string }> }
) {
  const requestId = getRequestId(req);

  try {
    const auth = authenticateAgentByToken(req, requestId);
    if (!auth.ok) {
      return auth.response;
    }

    const { tradeId } = await context.params;

    const trade = await dbQuery<{
      trade_id: string;
      source_trade_id: string | null;
      agent_id: string;
      chain_key: string;
      is_mock: boolean;
      status: string;
      token_in: string;
      token_out: string;
      amount_in: string | null;
      amount_out: string | null;
      slippage_bps: number | null;
      reason_code: string | null;
      reason_message: string | null;
      tx_hash: string | null;
      mock_receipt_id: string | null;
      created_at: string;
      updated_at: string;
    }>(
      `
      select
        trade_id,
        source_trade_id,
        agent_id,
        chain_key,
        is_mock,
        status,
        token_in,
        token_out,
        amount_in::text,
        amount_out::text,
        slippage_bps,
        reason_code,
        reason_message,
        tx_hash,
        mock_receipt_id,
        created_at::text,
        updated_at::text
      from trades
      where trade_id = $1
      limit 1
      `,
      [tradeId]
    );

    if (trade.rowCount === 0) {
      return errorResponse(
        404,
        {
          code: 'payload_invalid',
          message: 'Trade was not found.',
          actionHint: 'Verify tradeId and retry.'
        },
        requestId
      );
    }

    const row = trade.rows[0];
    if (row.agent_id !== auth.agentId) {
      return errorResponse(
        401,
        {
          code: 'auth_invalid',
          message: 'Authenticated agent is not allowed to read this trade.',
          actionHint: 'Use bearer token for the trade owner agent.'
        },
        requestId
      );
    }

    const rootTradeId = row.source_trade_id ?? row.trade_id;
    const failed = await dbQuery<{ count: string }>(
      `
      select count(*)::text as count
      from trades
      where agent_id = $1
        and chain_key = $2
        and status = 'failed'
        and (trade_id = $3 or source_trade_id = $3)
      `,
      [auth.agentId, row.chain_key, rootTradeId]
    );

    const failedAttempts = Number(failed.rows[0]?.count ?? '0');
    const ageMs = Math.max(0, Date.now() - new Date(row.updated_at).getTime());
    const retryEligible =
      row.status === 'failed' &&
      RETRYABLE_REASON_CODES.has((row.reason_code ?? '').toLowerCase()) &&
      failedAttempts < MAX_RETRIES &&
      ageMs <= RETRY_WINDOW_SECONDS * 1000;

    return successResponse(
      {
        ok: true,
        trade: {
          tradeId: row.trade_id,
          sourceTradeId: row.source_trade_id,
          agentId: row.agent_id,
          chainKey: row.chain_key,
          mode: row.is_mock ? 'mock' : 'real',
          status: row.status,
          tokenIn: row.token_in,
          tokenOut: row.token_out,
          amountIn: row.amount_in,
          amountOut: row.amount_out,
          slippageBps: row.slippage_bps,
          reasonCode: row.reason_code,
          reasonMessage: row.reason_message,
          txHash: row.tx_hash,
          mockReceiptId: row.mock_receipt_id,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          retry: {
            failedAttempts,
            maxRetries: MAX_RETRIES,
            retryWindowSec: RETRY_WINDOW_SECONDS,
            eligible: retryEligible
          }
        }
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
