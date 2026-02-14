import type { NextRequest } from 'next/server';

import { issueSignedAgentToken } from '@/lib/agent-token';
import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { makeId } from '@/lib/ids';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type BootstrapRequest = {
  agentName?: string;
  runtimePlatform?: 'windows' | 'linux' | 'macos';
  chainKey?: string;
  walletAddress: string;
  mode?: 'mock' | 'real';
  approvalMode?: 'per_trade' | 'auto';
  publicStatus?: 'active' | 'offline' | 'degraded' | 'paused' | 'deactivated';
};

function normalizeAgentName(input: string | undefined, fallbackId: string): string {
  const candidate = (input || '').trim();
  if (!candidate) {
    const suffix = fallbackId.replace(/^ag_/, '').slice(0, 20);
    return `xclaw-${suffix}`;
  }
  return candidate.slice(0, 32);
}

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<BootstrapRequest>('agent-bootstrap-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Bootstrap payload does not match schema.',
          actionHint: 'Provide walletAddress and optional runtime/bootstrap fields.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;
    const agentId = makeId('ag');
    const agentName = normalizeAgentName(body.agentName, agentId);
    const runtimePlatform = body.runtimePlatform ?? 'linux';
    const chainKey = body.chainKey ?? 'base_sepolia';
    const mode = body.mode ?? 'mock';
    const approvalMode = body.approvalMode ?? 'per_trade';
    const publicStatus = body.publicStatus ?? 'active';

    const agentApiKey = issueSignedAgentToken(agentId);
    if (!agentApiKey) {
      return errorResponse(
        503,
        {
          code: 'internal_error',
          message: 'Agent bootstrap token signing is not configured.',
          actionHint: 'Set XCLAW_AGENT_TOKEN_SIGNING_KEY (or XCLAW_MANAGEMENT_TOKEN_ENC_KEY) on the server and retry.'
        },
        requestId
      );
    }

    await withTransaction(async (client) => {
      await client.query(
        `
        insert into agents (
          agent_id, agent_name, runtime_platform, public_status, openclaw_metadata, created_at, updated_at
        ) values ($1, $2, $3, $4, '{}'::jsonb, now(), now())
        `,
        [agentId, agentName, runtimePlatform, publicStatus]
      );

      await client.query(
        `
        insert into agent_wallets (
          wallet_id, agent_id, chain_key, address, custody, created_at, updated_at
        ) values ($1, $2, $3, $4, 'agent_local', now(), now())
        `,
        [makeId('wlt'), agentId, chainKey, body.walletAddress]
      );

      await client.query(
        `
        insert into agent_policy_snapshots (
          snapshot_id, agent_id, mode, approval_mode, max_trade_usd, max_daily_usd, allowed_tokens, created_at
        ) values ($1, $2, $3, $4, null, null, '[]'::jsonb, now())
        `,
        [makeId('aps'), agentId, mode, approvalMode]
      );

      await client.query(
        `
        insert into agent_events (event_id, agent_id, event_type, payload, created_at)
        values ($1, $2, 'heartbeat', $3::jsonb, now())
        `,
        [
          makeId('evt'),
          agentId,
          JSON.stringify({
            source: 'bootstrap',
            mode,
            approvalMode,
            chainKey
          })
        ]
      );
    });

    return successResponse(
      {
        ok: true,
        agentId,
        agentName,
        chainKey,
        mode,
        approvalMode,
        publicStatus,
        agentApiKey
      },
      200,
      requestId
    );
  } catch (error) {
    const maybeCode = (error as { code?: string }).code;
    const maybeConstraint = (error as { constraint?: string }).constraint;
    if (maybeCode === '23505') {
      if (maybeConstraint === 'agents_agent_name_key' || maybeConstraint === 'idx_agents_agent_name') {
        return errorResponse(
          409,
          {
            code: 'payload_invalid',
            message:
              'Agent name already exists. Bootstrap was rolled back and no partial registration was stored.',
            actionHint: 'Choose a different agentName and rerun the same bootstrap command.',
            details: { field: 'agentName', conflict: 'already_exists', constraint: maybeConstraint }
          },
          requestId
        );
      }
      return errorResponse(
        409,
        {
          code: 'payload_invalid',
          message: 'Bootstrap failed due to uniqueness collision; retry.',
          actionHint: 'Retry bootstrap; a fresh agent id will be generated.'
        },
        requestId
      );
    }

    return internalErrorResponse(requestId);
  }
}
