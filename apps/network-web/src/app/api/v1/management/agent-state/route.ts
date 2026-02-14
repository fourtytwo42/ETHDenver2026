import type { NextRequest } from 'next/server';

import { dbQuery } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { requireManagementSession } from '@/lib/management-auth';
import { STEPUP_COOKIE_NAME } from '@/lib/management-cookies';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

export async function GET(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const agentId = req.nextUrl.searchParams.get('agentId');
    if (!agentId) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'agentId query parameter is required.',
          actionHint: 'Provide ?agentId=<agent-id>.'
        },
        requestId
      );
    }

    const auth = await requireManagementSession(req, requestId);
    if (!auth.ok) {
      return auth.response;
    }

    if (auth.session.agentId !== agentId) {
      return errorResponse(
        401,
        {
          code: 'auth_invalid',
          message: 'Management session is not authorized for this agent.',
          actionHint: 'Use the matching agent session for this route.'
        },
        requestId
      );
    }

    const [agent, approvals, policy, audit] = await Promise.all([
      dbQuery<{
        agent_id: string;
        public_status: string;
        openclaw_metadata: Record<string, unknown> | null;
      }>(
        `
        select agent_id, public_status, openclaw_metadata
        from agents
        where agent_id = $1
        limit 1
        `,
        [agentId]
      ),
      dbQuery<{
        trade_id: string;
        chain_key: string;
        pair: string;
        amount_in: string | null;
        token_in: string;
        token_out: string;
        reason: string | null;
        created_at: string;
      }>(
        `
        select trade_id, chain_key, pair, amount_in::text, token_in, token_out, reason, created_at::text
        from trades
        where agent_id = $1
          and status = 'approval_pending'
        order by created_at asc
        limit 50
        `,
        [agentId]
      ),
      dbQuery<{
        mode: 'mock' | 'real';
        approval_mode: 'per_trade' | 'auto';
        max_trade_usd: string | null;
        max_daily_usd: string | null;
        allowed_tokens: string[];
        created_at: string;
      }>(
        `
        select mode, approval_mode, max_trade_usd::text, max_daily_usd::text, allowed_tokens, created_at::text
        from agent_policy_snapshots
        where agent_id = $1
        order by created_at desc
        limit 1
        `,
        [agentId]
      ),
      dbQuery<{
        audit_id: string;
        action_type: string;
        action_status: string;
        public_redacted_payload: Record<string, unknown>;
        created_at: string;
      }>(
        `
        select audit_id, action_type, action_status, public_redacted_payload, created_at::text
        from management_audit_log
        where agent_id = $1
        order by created_at desc
        limit 25
        `,
        [agentId]
      )
    ]);

    if (agent.rowCount === 0) {
      return errorResponse(
        404,
        {
          code: 'payload_invalid',
          message: 'Agent was not found.',
          actionHint: 'Verify agentId and retry.'
        },
        requestId
      );
    }

    const stepupCookie = req.cookies.get(STEPUP_COOKIE_NAME)?.value;
    let stepup: { active: boolean; expiresAt: string | null } = { active: false, expiresAt: null };

    if (stepupCookie) {
      const stepupResult = await dbQuery<{ expires_at: string; revoked_at: string | null }>(
        `
        select expires_at::text, revoked_at::text
        from stepup_sessions
        where stepup_session_id = $1
          and agent_id = $2
          and management_session_id = $3
        limit 1
        `,
        [stepupCookie, agentId, auth.session.sessionId]
      );

      if ((stepupResult.rowCount ?? 0) > 0) {
        const row = stepupResult.rows[0];
        const active = !row.revoked_at && new Date(row.expires_at).getTime() > Date.now();
        stepup = { active, expiresAt: row.expires_at };
      }
    }

    return successResponse(
      {
        ok: true,
        agent: {
          agentId: agent.rows[0].agent_id,
          publicStatus: agent.rows[0].public_status,
          metadata: agent.rows[0].openclaw_metadata ?? {}
        },
        approvalsQueue: approvals.rows,
        latestPolicy: policy.rows[0] ?? null,
        auditLog: audit.rows,
        stepup,
        managementSession: {
          sessionId: auth.session.sessionId,
          expiresAt: auth.session.expiresAt
        }
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
