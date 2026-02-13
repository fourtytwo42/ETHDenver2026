import type { NextRequest } from 'next/server';

import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { makeId } from '@/lib/ids';
import { requireManagementWriteAuth, requireStepupSession } from '@/lib/management-auth';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type ApprovalScopeRequest = {
  agentId: string;
  chainKey: string;
  scope: 'pair' | 'global';
  action: 'grant' | 'revoke';
  pairRef?: string;
  maxAmountUsd?: string;
  slippageBpsMax?: number;
  expiresAt?: string;
};

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<ApprovalScopeRequest>('management-approval-scope-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Approval scope payload does not match schema.',
          actionHint: 'Provide scope action fields with valid chain and limits.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;
    if (body.scope === 'pair' && !body.pairRef) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'pairRef is required for pair scope approvals.',
          actionHint: 'Provide pairRef when scope=pair.'
        },
        requestId
      );
    }

    const auth = await requireManagementWriteAuth(req, requestId, body.agentId);
    if (!auth.ok) {
      return auth.response;
    }

    const stepup = await requireStepupSession(req, requestId, body.agentId, auth.session.sessionId);
    if (!stepup.ok) {
      return stepup.response;
    }

    const result = await withTransaction(async (client) => {
      if (body.action === 'grant') {
        const approvalId = makeId('apr');
        await client.query(
          `
          insert into approvals (
            approval_id, agent_id, chain_key, scope, status, trade_ref, pair_ref, requires_stepup,
            granted_by_session_id, direction, max_amount_usd, slippage_bps_max,
            resubmit_window_sec, resubmit_amount_tolerance_bps, max_retries, expires_at, created_at, updated_at
          ) values (
            $1, $2, $3, $4::approval_scope, 'active', null, $5, true,
            $6, 'non_directional', $7::numeric, $8,
            600, 1000, 3, $9::timestamptz, now(), now()
          )
          `,
          [
            approvalId,
            body.agentId,
            body.chainKey,
            body.scope,
            body.scope === 'pair' ? body.pairRef ?? null : null,
            auth.session.sessionId,
            body.maxAmountUsd ?? '50',
            body.slippageBpsMax ?? 50,
            body.expiresAt ?? new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
          ]
        );

        return { action: 'grant' as const, approvalId };
      }

      const revoked = await client.query(
        `
        update approvals
        set status = 'revoked'::approval_status,
            updated_at = now()
        where agent_id = $1
          and chain_key = $2
          and scope = $3::approval_scope
          and status = 'active'::approval_status
          and (($3::approval_scope = 'pair'::approval_scope and pair_ref = $4) or ($3::approval_scope = 'global'::approval_scope))
        returning approval_id
        `,
        [body.agentId, body.chainKey, body.scope, body.pairRef ?? null]
      );

      return { action: 'revoke' as const, revokedCount: revoked.rowCount ?? 0 };
    });

    await withTransaction(async (client) => {
      await client.query(
        `
        insert into management_audit_log (
          audit_id, agent_id, management_session_id, action_type, action_status,
          public_redacted_payload, private_payload, user_agent, created_at
        ) values ($1, $2, $3, 'approval.scope', 'accepted', $4::jsonb, $5::jsonb, $6, now())
        `,
        [
          makeId('aud'),
          body.agentId,
          auth.session.sessionId,
          JSON.stringify({ action: body.action, scope: body.scope, chainKey: body.chainKey }),
          JSON.stringify({ pairRef: body.pairRef ?? null, result }),
          req.headers.get('user-agent')
        ]
      );
    });

    return successResponse({ ok: true, result }, 200, requestId);
  } catch {
    return internalErrorResponse(requestId);
  }
}
