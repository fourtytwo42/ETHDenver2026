import type { NextRequest } from 'next/server';

import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { makeId } from '@/lib/ids';
import { requireManagementWriteAuth } from '@/lib/management-auth';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type OffdexDecisionRequest = {
  agentId: string;
  intentId: string;
  action: 'approve' | 'cancel' | 'settle_request';
  reasonCode?: string;
  reasonMessage?: string;
};

const NEXT_STATUS: Record<OffdexDecisionRequest['action'], string> = {
  approve: 'accepted',
  cancel: 'cancelled',
  settle_request: 'settling'
};

function canTransition(action: OffdexDecisionRequest['action'], current: string): boolean {
  if (action === 'approve') {
    return current === 'proposed';
  }
  if (action === 'cancel') {
    return current === 'proposed' || current === 'accepted' || current === 'ready_to_settle';
  }
  return current === 'ready_to_settle';
}

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<OffdexDecisionRequest>('management-offdex-decision-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Off-DEX decision payload does not match schema.',
          actionHint: 'Provide agentId, intentId, and action.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;
    const auth = await requireManagementWriteAuth(req, requestId, body.agentId);
    if (!auth.ok) {
      return auth.response;
    }

    const result = await withTransaction(async (client) => {
      const intent = await client.query<{ status: string; maker_agent_id: string; taker_agent_id: string | null }>(
        `
        select status, maker_agent_id, taker_agent_id
        from offdex_settlement_intents
        where settlement_intent_id = $1
        limit 1
        `,
        [body.intentId]
      );

      if (intent.rowCount === 0) {
        return { ok: false as const, kind: 'missing' as const };
      }

      const row = intent.rows[0];
      if (row.maker_agent_id !== body.agentId && row.taker_agent_id !== body.agentId) {
        return { ok: false as const, kind: 'auth' as const };
      }

      if (!canTransition(body.action, row.status)) {
        return { ok: false as const, kind: 'transition' as const, currentStatus: row.status };
      }

      await client.query(
        `
        update offdex_settlement_intents
        set
          status = $1::offdex_settlement_status,
          failure_code = $2,
          failure_message = $3,
          updated_at = now()
        where settlement_intent_id = $4
        `,
        [NEXT_STATUS[body.action], body.reasonCode ?? null, body.reasonMessage ?? null, body.intentId]
      );

      await client.query(
        `
        insert into management_audit_log (
          audit_id, agent_id, management_session_id, action_type, action_status,
          public_redacted_payload, private_payload, user_agent, created_at
        ) values ($1, $2, $3, 'offdex.decision', 'accepted', $4::jsonb, $5::jsonb, $6, now())
        `,
        [
          makeId('aud'),
          body.agentId,
          auth.session.sessionId,
          JSON.stringify({ intentId: body.intentId, action: body.action, status: NEXT_STATUS[body.action] }),
          JSON.stringify({ reasonCode: body.reasonCode ?? null, reasonMessage: body.reasonMessage ?? null }),
          req.headers.get('user-agent')
        ]
      );

      return { ok: true as const, status: NEXT_STATUS[body.action] };
    });

    if (!result.ok) {
      if (result.kind === 'missing') {
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

      if (result.kind === 'auth') {
        return errorResponse(
          401,
          {
            code: 'auth_invalid',
            message: 'Agent is not part of this off-DEX intent.',
            actionHint: 'Use the management session for a participating agent.'
          },
          requestId
        );
      }

      return errorResponse(
        409,
        {
          code: 'trade_invalid_transition',
          message: 'Off-DEX action is not allowed from current status.',
          actionHint: 'Refresh intent queue and retry with an allowed transition.',
          details: { currentStatus: result.currentStatus }
        },
        requestId
      );
    }

    return successResponse({ ok: true, intentId: body.intentId, status: result.status }, 200, requestId);
  } catch {
    return internalErrorResponse(requestId);
  }
}
