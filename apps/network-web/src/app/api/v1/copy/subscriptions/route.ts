import type { NextRequest } from 'next/server';

import { dbQuery, withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { requireManagementSession, requireManagementWriteAuth } from '@/lib/management-auth';
import { recomputeMetricsForAgents } from '@/lib/metrics';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';
import { makeId } from '@/lib/ids';

export const runtime = 'nodejs';

type CopySubscriptionCreateRequest = {
  leaderAgentId: string;
  followerAgentId: string;
  enabled: boolean;
  scaleBps: number;
  maxTradeUsd: string;
  allowedTokens?: string[];
};

export async function GET(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const auth = await requireManagementSession(req, requestId);
    if (!auth.ok) {
      return auth.response;
    }

    const rows = await dbQuery<{
      subscription_id: string;
      leader_agent_id: string;
      follower_agent_id: string;
      enabled: boolean;
      scale_bps: number;
      max_trade_usd: string | null;
      allowed_tokens: string[] | null;
      created_at: string;
      updated_at: string;
    }>(
      `
      select
        subscription_id,
        leader_agent_id,
        follower_agent_id,
        enabled,
        scale_bps,
        max_trade_usd::text,
        allowed_tokens,
        created_at::text,
        updated_at::text
      from copy_subscriptions
      where follower_agent_id = $1
      order by created_at desc
      `,
      [auth.session.agentId]
    );

    return successResponse(
      {
        ok: true,
        followerAgentId: auth.session.agentId,
        items: rows.rows.map((row) => ({
          subscriptionId: row.subscription_id,
          leaderAgentId: row.leader_agent_id,
          followerAgentId: row.follower_agent_id,
          enabled: row.enabled,
          scaleBps: row.scale_bps,
          maxTradeUsd: row.max_trade_usd,
          allowedTokens: row.allowed_tokens ?? [],
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

    const validated = validatePayload<CopySubscriptionCreateRequest>('copy-subscription-create-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Copy subscription payload does not match schema.',
          actionHint: 'Provide valid leader/follower IDs, limits, and token allowlist values.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;
    if (body.leaderAgentId === body.followerAgentId) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Follower cannot subscribe to itself.',
          actionHint: 'Use a different leaderAgentId.'
        },
        requestId
      );
    }

    const auth = await requireManagementWriteAuth(req, requestId, body.followerAgentId);
    if (!auth.ok) {
      return auth.response;
    }

    const result = await withTransaction(async (client) => {
      const agents = await client.query<{ agent_id: string }>(
        `
        select agent_id
        from agents
        where agent_id = any($1::text[])
        `,
        [[body.leaderAgentId, body.followerAgentId]]
      );

      const seen = new Set(agents.rows.map((row) => row.agent_id));
      if (!seen.has(body.leaderAgentId) || !seen.has(body.followerAgentId)) {
        return { ok: false as const, kind: 'missing_agent' as const };
      }

      const upsert = await client.query<{
        subscription_id: string;
        leader_agent_id: string;
        follower_agent_id: string;
        enabled: boolean;
        scale_bps: number;
        max_trade_usd: string | null;
        allowed_tokens: string[] | null;
        created_at: string;
        updated_at: string;
      }>(
        `
        insert into copy_subscriptions (
          subscription_id,
          leader_agent_id,
          follower_agent_id,
          enabled,
          scale_bps,
          max_trade_usd,
          allowed_tokens,
          created_at,
          updated_at
        ) values (
          $1, $2, $3, $4, $5, $6::numeric, $7::jsonb, now(), now()
        )
        on conflict (leader_agent_id, follower_agent_id)
        do update
        set
          enabled = excluded.enabled,
          scale_bps = excluded.scale_bps,
          max_trade_usd = excluded.max_trade_usd,
          allowed_tokens = excluded.allowed_tokens,
          updated_at = now()
        returning
          subscription_id,
          leader_agent_id,
          follower_agent_id,
          enabled,
          scale_bps,
          max_trade_usd::text,
          allowed_tokens,
          created_at::text,
          updated_at::text
        `,
        [
          makeId('cps'),
          body.leaderAgentId,
          body.followerAgentId,
          body.enabled,
          body.scaleBps,
          body.maxTradeUsd,
          JSON.stringify(body.allowedTokens ?? [])
        ]
      );

      await recomputeMetricsForAgents(client, [body.leaderAgentId, body.followerAgentId]);
      return { ok: true as const, row: upsert.rows[0] };
    });

    if (!result.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Leader or follower agent does not exist.',
          actionHint: 'Verify leaderAgentId and followerAgentId before retrying.'
        },
        requestId
      );
    }

    return successResponse(
      {
        ok: true,
        subscription: {
          subscriptionId: result.row.subscription_id,
          leaderAgentId: result.row.leader_agent_id,
          followerAgentId: result.row.follower_agent_id,
          enabled: result.row.enabled,
          scaleBps: result.row.scale_bps,
          maxTradeUsd: result.row.max_trade_usd,
          allowedTokens: result.row.allowed_tokens ?? [],
          createdAt: result.row.created_at,
          updatedAt: result.row.updated_at
        }
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
