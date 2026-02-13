import type { NextRequest } from 'next/server';

import { authenticateAgentByToken } from '@/lib/agent-auth';
import { dbQuery } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseIntQuery } from '@/lib/http';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

const RETRY_WINDOW_SECONDS = 600;
const MAX_RETRIES = 3;
const RETRYABLE_REASON_CODES = new Set(['rpc_unavailable', 'verification_timeout', 'slippage_exceeded']);

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

    const limit = parseIntQuery(req.nextUrl.searchParams.get('limit'), 25, 1, 100);

    const result = await dbQuery<{
      trade_id: string;
      source_trade_id: string | null;
      status: string;
      reason_code: string | null;
      reason_message: string | null;
      is_mock: boolean;
      token_in: string;
      token_out: string;
      amount_in: string | null;
      slippage_bps: number | null;
      tx_hash: string | null;
      mock_receipt_id: string | null;
      updated_at: string;
      created_at: string;
      failed_attempts: string;
    }>(
      `
      with base as (
        select
          t.trade_id,
          t.source_trade_id,
          coalesce(t.source_trade_id, t.trade_id) as root_trade_id,
          t.status,
          t.reason_code,
          t.reason_message,
          t.is_mock,
          t.token_in,
          t.token_out,
          t.amount_in::text,
          t.slippage_bps,
          t.tx_hash,
          t.mock_receipt_id,
          t.updated_at::text,
          t.created_at::text
        from trades t
        where t.agent_id = $1
          and t.chain_key = $2
          and t.status in ('approved', 'failed')
      )
      select
        b.trade_id,
        b.source_trade_id,
        b.status,
        b.reason_code,
        b.reason_message,
        b.is_mock,
        b.token_in,
        b.token_out,
        b.amount_in,
        b.slippage_bps,
        b.tx_hash,
        b.mock_receipt_id,
        b.updated_at,
        b.created_at,
        (
          select count(*)::text
          from trades t2
          where t2.agent_id = $1
            and t2.chain_key = $2
            and t2.status = 'failed'
            and (t2.trade_id = b.root_trade_id or t2.source_trade_id = b.root_trade_id)
        ) as failed_attempts
      from base b
      order by b.created_at asc
      limit $3
      `,
      [auth.agentId, chainKey, limit]
    );

    const nowMs = Date.now();
    const items = result.rows
      .map((row) => {
        const failedAttempts = Number(row.failed_attempts);
        const ageMs = Math.max(0, nowMs - new Date(row.updated_at).getTime());
        const retryEligible =
          row.status === 'failed' &&
          RETRYABLE_REASON_CODES.has((row.reason_code ?? '').toLowerCase()) &&
          failedAttempts < MAX_RETRIES &&
          ageMs <= RETRY_WINDOW_SECONDS * 1000;

        const actionable = row.status === 'approved' || retryEligible;

        return {
          tradeId: row.trade_id,
          sourceTradeId: row.source_trade_id,
          status: row.status,
          mode: row.is_mock ? 'mock' : 'real',
          tokenIn: row.token_in,
          tokenOut: row.token_out,
          amountIn: row.amount_in,
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
          },
          actionable
        };
      })
      .filter((item) => item.actionable);

    return successResponse(
      {
        ok: true,
        agentId: auth.agentId,
        chainKey,
        limit,
        items
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
