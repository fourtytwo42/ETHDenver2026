import type { NextRequest } from 'next/server';

import { authenticateAgentByToken, requireAgentAuth } from '@/lib/agent-auth';
import { dbQuery, withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody, parseIntQuery } from '@/lib/http';
import { ensureIdempotency, storeIdempotencyResponse } from '@/lib/idempotency';
import { makeId } from '@/lib/ids';
import { deriveFundingStatus, isOffdexExpired, isOffdexTerminalStatus } from '@/lib/offdex-state';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type OffdexIntentCreateRequest = {
  schemaVersion: number;
  chainKey: string;
  makerAgentId: string;
  takerAgentId?: string;
  makerWalletAddress: string;
  makerToken: string;
  takerToken: string;
  makerAmount: string;
  takerAmount: string;
  escrowContract: string;
  expiresAt: string;
};

async function expireIntentIfNeeded(intentId: string): Promise<void> {
  await dbQuery(
    `
    update offdex_settlement_intents
    set status = 'expired'::offdex_settlement_status, updated_at = now()
    where settlement_intent_id = $1
      and status not in ('settled', 'cancelled', 'expired', 'failed')
      and expires_at <= now()
    `,
    [intentId]
  );
}

export async function GET(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const auth = authenticateAgentByToken(req, requestId);
    if (!auth.ok) {
      return auth.response;
    }

    const queryAgentId = req.nextUrl.searchParams.get('agentId')?.trim();
    if (queryAgentId && queryAgentId !== auth.agentId) {
      return errorResponse(
        401,
        {
          code: 'auth_invalid',
          message: 'Authenticated agent cannot query intents for another agent.',
          actionHint: 'Remove agentId query or set it to your authenticated agent.'
        },
        requestId
      );
    }

    const statusFilter = req.nextUrl.searchParams.get('status')?.trim() || null;
    const chainFilter = req.nextUrl.searchParams.get('chain')?.trim() || null;
    const limit = parseIntQuery(req.nextUrl.searchParams.get('limit'), 50, 1, 200);

    await dbQuery(
      `
      update offdex_settlement_intents
      set status = 'expired'::offdex_settlement_status, updated_at = now()
      where status not in ('settled', 'cancelled', 'expired', 'failed')
        and expires_at <= now()
        and (maker_agent_id = $1 or taker_agent_id = $1)
      `,
      [auth.agentId]
    );

    const result = await dbQuery<{
      settlement_intent_id: string;
      chain_key: string;
      maker_agent_id: string;
      taker_agent_id: string | null;
      maker_wallet_address: string;
      taker_wallet_address: string | null;
      maker_token: string;
      taker_token: string;
      maker_amount: string;
      taker_amount: string;
      escrow_contract: string;
      escrow_deal_id: string | null;
      maker_fund_tx_hash: string | null;
      taker_fund_tx_hash: string | null;
      settlement_tx_hash: string | null;
      status: string;
      failure_code: string | null;
      failure_message: string | null;
      expires_at: string;
      created_at: string;
      updated_at: string;
    }>(
      `
      select
        settlement_intent_id,
        chain_key,
        maker_agent_id,
        taker_agent_id,
        maker_wallet_address,
        taker_wallet_address,
        maker_token,
        taker_token,
        maker_amount::text,
        taker_amount::text,
        escrow_contract,
        escrow_deal_id,
        maker_fund_tx_hash,
        taker_fund_tx_hash,
        settlement_tx_hash,
        status,
        failure_code,
        failure_message,
        expires_at::text,
        created_at::text,
        updated_at::text
      from offdex_settlement_intents
      where (maker_agent_id = $1 or taker_agent_id = $1)
        and ($2::text is null or status = $2::offdex_settlement_status)
        and ($3::text is null or chain_key = $3)
      order by created_at desc
      limit $4
      `,
      [auth.agentId, statusFilter, chainFilter, limit]
    );

    return successResponse(
      {
        ok: true,
        agentId: auth.agentId,
        limit,
        items: result.rows.map((row) => ({
          settlementIntentId: row.settlement_intent_id,
          chainKey: row.chain_key,
          makerAgentId: row.maker_agent_id,
          takerAgentId: row.taker_agent_id,
          makerWalletAddress: row.maker_wallet_address,
          takerWalletAddress: row.taker_wallet_address,
          makerToken: row.maker_token,
          takerToken: row.taker_token,
          makerAmount: row.maker_amount,
          takerAmount: row.taker_amount,
          escrowContract: row.escrow_contract,
          escrowDealId: row.escrow_deal_id,
          makerFundTxHash: row.maker_fund_tx_hash,
          takerFundTxHash: row.taker_fund_tx_hash,
          settlementTxHash: row.settlement_tx_hash,
          status: deriveFundingStatus(row),
          failureCode: row.failure_code,
          failureMessage: row.failure_message,
          expiresAt: row.expires_at,
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

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<OffdexIntentCreateRequest>('offdex-intent-create-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Off-DEX intent payload does not match schema.',
          actionHint: 'Check required fields and address formats.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;
    const auth = requireAgentAuth(req, body.makerAgentId, requestId);
    if (!auth.ok) {
      return auth.response;
    }

    const expiresMs = new Date(body.expiresAt).getTime();
    if (!Number.isFinite(expiresMs) || expiresMs <= Date.now()) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'expiresAt must be a valid future UTC timestamp.',
          actionHint: 'Set expiresAt to a future ISO-8601 timestamp.'
        },
        requestId
      );
    }

    const idempotency = await ensureIdempotency(req, 'offdex_create', body.makerAgentId, body, requestId);
    if (!idempotency.ok) {
      return idempotency.response;
    }
    if (idempotency.ctx.replayResponse) {
      return successResponse(idempotency.ctx.replayResponse.body, idempotency.ctx.replayResponse.status, requestId);
    }

    const settlementIntentId = makeId('ofi');
    const insert = await withTransaction(async (client) => {
      const maker = await client.query('select agent_id from agents where agent_id = $1 limit 1', [body.makerAgentId]);
      if (maker.rowCount === 0) {
        return { ok: false as const, kind: 'maker_missing' as const };
      }
      if (body.takerAgentId) {
        const taker = await client.query('select agent_id from agents where agent_id = $1 limit 1', [body.takerAgentId]);
        if (taker.rowCount === 0) {
          return { ok: false as const, kind: 'taker_missing' as const };
        }
      }

      await client.query(
        `
        insert into offdex_settlement_intents (
          settlement_intent_id,
          chain_key,
          maker_agent_id,
          taker_agent_id,
          maker_wallet_address,
          maker_token,
          taker_token,
          maker_amount,
          taker_amount,
          escrow_contract,
          status,
          expires_at,
          created_at,
          updated_at
        ) values (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'proposed'::offdex_settlement_status, $11::timestamptz, now(), now()
        )
        `,
        [
          settlementIntentId,
          body.chainKey,
          body.makerAgentId,
          body.takerAgentId ?? null,
          body.makerWalletAddress,
          body.makerToken,
          body.takerToken,
          body.makerAmount,
          body.takerAmount,
          body.escrowContract,
          body.expiresAt
        ]
      );

      await client.query(
        `
        insert into management_audit_log (
          audit_id, agent_id, management_session_id, action_type, action_status, public_redacted_payload, private_payload, user_agent, created_at
        ) values ($1, $2, null, 'offdex.intent.create', 'accepted', $3::jsonb, $4::jsonb, $5, now())
        `,
        [
          makeId('aud'),
          body.makerAgentId,
          JSON.stringify({ settlementIntentId, chainKey: body.chainKey, status: 'proposed' }),
          JSON.stringify({ makerAmount: body.makerAmount, takerAmount: body.takerAmount }),
          req.headers.get('user-agent')
        ]
      );

      return { ok: true as const };
    });

    if (!insert.ok) {
      if (insert.kind === 'maker_missing') {
        return errorResponse(
          400,
          {
            code: 'payload_invalid',
            message: 'makerAgentId is not a registered agent.',
            actionHint: 'Register maker agent before creating off-DEX intents.'
          },
          requestId
        );
      }
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'takerAgentId is not a registered agent.',
          actionHint: 'Use a valid takerAgentId or omit it for open intent.'
        },
        requestId
      );
    }

    await expireIntentIfNeeded(settlementIntentId);
    const row = await dbQuery<{ status: string }>(
      'select status from offdex_settlement_intents where settlement_intent_id = $1 limit 1',
      [settlementIntentId]
    );
    const status = row.rows[0]?.status ?? 'proposed';
    const responseBody = { ok: true, settlementIntentId, status: isOffdexTerminalStatus(status) ? status : 'proposed' };
    await storeIdempotencyResponse(idempotency.ctx, 200, responseBody);
    return successResponse(responseBody, 200, requestId);
  } catch {
    return internalErrorResponse(requestId);
  }
}
