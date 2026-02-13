import type { NextRequest } from 'next/server';

import { authenticateAgentByToken } from '@/lib/agent-auth';
import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { ensureIdempotency, storeIdempotencyResponse } from '@/lib/idempotency';
import { makeId } from '@/lib/ids';
import { canAcceptOffdexIntent, isOffdexExpired, type OffdexIntentRow } from '@/lib/offdex-state';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

export async function POST(
  req: NextRequest,
  context: { params: Promise<{ intentId: string }> }
) {
  const requestId = getRequestId(req);

  try {
    const auth = authenticateAgentByToken(req, requestId);
    if (!auth.ok) {
      return auth.response;
    }

    const { intentId } = await context.params;
    const idempotency = await ensureIdempotency(req, 'offdex_accept', auth.agentId, { intentId }, requestId);
    if (!idempotency.ok) {
      return idempotency.response;
    }
    if (idempotency.ctx.replayResponse) {
      return successResponse(idempotency.ctx.replayResponse.body, idempotency.ctx.replayResponse.status, requestId);
    }

    const update = await withTransaction(async (client) => {
      await client.query(
        `
        update offdex_settlement_intents
        set status = 'expired'::offdex_settlement_status, updated_at = now()
        where settlement_intent_id = $1
          and status not in ('settled', 'cancelled', 'expired', 'failed')
          and expires_at <= now()
        `,
        [intentId]
      );

      const intent = await client.query<
        OffdexIntentRow & {
          settlement_intent_id: string;
          chain_key: string;
        }
      >(
        `
        select settlement_intent_id, chain_key, status, maker_agent_id, taker_agent_id, expires_at::text, maker_fund_tx_hash, taker_fund_tx_hash
        from offdex_settlement_intents
        where settlement_intent_id = $1
        limit 1
        `,
        [intentId]
      );
      if (intent.rowCount === 0) {
        return { ok: false as const, kind: 'missing' as const };
      }

      const row = intent.rows[0];
      if (isOffdexExpired(row, Date.now())) {
        return { ok: false as const, kind: 'expired' as const };
      }
      if (!canAcceptOffdexIntent(row, auth.agentId)) {
        return { ok: false as const, kind: 'invalid' as const, currentStatus: row.status };
      }

      const takerWallet = await client.query<{ address: string }>(
        `
        select address
        from agent_wallets
        where agent_id = $1
          and chain_key = $2
        order by created_at desc
        limit 1
        `,
        [auth.agentId, row.chain_key]
      );
      if (takerWallet.rowCount === 0) {
        return { ok: false as const, kind: 'wallet_missing' as const, chainKey: row.chain_key };
      }

      await client.query(
        `
        update offdex_settlement_intents
        set
          taker_agent_id = $1,
          taker_wallet_address = $2,
          status = 'accepted'::offdex_settlement_status,
          updated_at = now()
        where settlement_intent_id = $3
        `,
        [auth.agentId, takerWallet.rows[0].address, intentId]
      );

      await client.query(
        `
        insert into management_audit_log (
          audit_id, agent_id, management_session_id, action_type, action_status, public_redacted_payload, private_payload, user_agent, created_at
        ) values ($1, $2, null, 'offdex.intent.accept', 'accepted', $3::jsonb, $4::jsonb, $5, now())
        `,
        [
          makeId('aud'),
          auth.agentId,
          JSON.stringify({ settlementIntentId: intentId, status: 'accepted' }),
          JSON.stringify({ chainKey: row.chain_key }),
          req.headers.get('user-agent')
        ]
      );

      return { ok: true as const };
    });

    if (!update.ok) {
      if (update.kind === 'missing') {
        return errorResponse(
          404,
          {
            code: 'payload_invalid',
            message: 'Off-DEX intent was not found.',
            actionHint: 'Verify intentId and retry.'
          },
          requestId
        );
      }
      if (update.kind === 'wallet_missing') {
        return errorResponse(
          400,
          {
            code: 'payload_invalid',
            message: 'Taker wallet is not registered for this chain.',
            actionHint: 'Register taker wallet for chain before accepting intent.',
            details: { chainKey: update.chainKey }
          },
          requestId
        );
      }
      if (update.kind === 'expired') {
        return errorResponse(
          409,
          {
            code: 'trade_invalid_transition',
            message: 'Off-DEX intent is expired and cannot be accepted.',
            actionHint: 'Create a new off-DEX intent with a future expiry.'
          },
          requestId
        );
      }
      return errorResponse(
        409,
        {
          code: 'trade_invalid_transition',
          message: 'Off-DEX intent cannot be accepted from current state.',
          actionHint: 'Refresh intent state and retry with an eligible taker.',
          details: { currentStatus: update.currentStatus }
        },
        requestId
      );
    }

    const responseBody = { ok: true, settlementIntentId: intentId, status: 'accepted' };
    await storeIdempotencyResponse(idempotency.ctx, 200, responseBody);
    return successResponse(responseBody, 200, requestId);
  } catch {
    return internalErrorResponse(requestId);
  }
}
