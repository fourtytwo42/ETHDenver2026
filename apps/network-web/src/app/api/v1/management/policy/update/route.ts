import type { NextRequest } from 'next/server';

import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { makeId } from '@/lib/ids';
import { requireManagementWriteAuth, requireStepupSession } from '@/lib/management-auth';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type PolicyUpdateRequest = {
  agentId: string;
  mode: 'mock' | 'real';
  approvalMode: 'per_trade' | 'auto';
  maxTradeUsd: string;
  maxDailyUsd: string;
  allowedTokens: string[];
  outboundTransfersEnabled?: boolean;
  outboundMode?: 'disabled' | 'allow_all' | 'whitelist';
  outboundWhitelistAddresses?: string[];
};

function normalizeWhitelist(values: string[] | undefined): string[] {
  if (!values) {
    return [];
  }
  const unique = new Set<string>();
  for (const value of values) {
    const normalized = value.trim().toLowerCase();
    if (/^0x[a-f0-9]{40}$/.test(normalized)) {
      unique.add(normalized);
    }
  }
  return [...unique];
}

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<PolicyUpdateRequest>('management-policy-update-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Policy update payload does not match schema.',
          actionHint: 'Provide all policy fields with canonical enum values.',
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

    const outboundFieldsTouched =
      typeof body.outboundTransfersEnabled === 'boolean' ||
      typeof body.outboundMode === 'string' ||
      Array.isArray(body.outboundWhitelistAddresses);

    if (outboundFieldsTouched) {
      const stepup = await requireStepupSession(req, requestId, body.agentId, auth.session.sessionId);
      if (!stepup.ok) {
        return stepup.response;
      }
    }

    const snapshotId = makeId('pol');
    const outboundTransfersEnabled = body.outboundTransfersEnabled ?? false;
    const outboundMode = body.outboundMode ?? (outboundTransfersEnabled ? 'allow_all' : 'disabled');
    const outboundWhitelistAddresses = normalizeWhitelist(body.outboundWhitelistAddresses);

    await withTransaction(async (client) => {
      await client.query(
        `
        insert into agent_policy_snapshots (
          snapshot_id, agent_id, mode, approval_mode, max_trade_usd, max_daily_usd, allowed_tokens, created_at
        ) values ($1, $2, $3::policy_mode, $4::policy_approval_mode, $5::numeric, $6::numeric, $7::jsonb, now())
        `,
        [snapshotId, body.agentId, body.mode, body.approvalMode, body.maxTradeUsd, body.maxDailyUsd, JSON.stringify(body.allowedTokens)]
      );

      await client.query(
        `
        insert into agent_transfer_policies (
          policy_id,
          agent_id,
          chain_key,
          outbound_transfers_enabled,
          outbound_mode,
          outbound_whitelist_addresses,
          updated_by_management_session_id,
          created_at,
          updated_at
        ) values ($1, $2, 'base_sepolia', $3, $4::outbound_transfer_mode, $5::jsonb, $6, now(), now())
        on conflict (agent_id, chain_key)
        do update set
          outbound_transfers_enabled = excluded.outbound_transfers_enabled,
          outbound_mode = excluded.outbound_mode,
          outbound_whitelist_addresses = excluded.outbound_whitelist_addresses,
          updated_by_management_session_id = excluded.updated_by_management_session_id,
          updated_at = now()
        `,
        [
          makeId('atp'),
          body.agentId,
          outboundTransfersEnabled,
          outboundMode,
          JSON.stringify(outboundWhitelistAddresses),
          auth.session.sessionId
        ]
      );

      await client.query(
        `
        insert into agent_events (event_id, agent_id, trade_id, event_type, payload, created_at)
        values ($1, $2, null, 'policy_changed', $3::jsonb, now())
        `,
        [
          makeId('evt'),
          body.agentId,
          JSON.stringify({
            mode: body.mode,
            approvalMode: body.approvalMode,
            maxTradeUsd: body.maxTradeUsd,
            maxDailyUsd: body.maxDailyUsd,
            allowedTokens: body.allowedTokens,
            outboundTransfersEnabled,
            outboundMode
          })
        ]
      );

      await client.query(
        `
        insert into management_audit_log (
          audit_id, agent_id, management_session_id, action_type, action_status,
          public_redacted_payload, private_payload, user_agent, created_at
        ) values ($1, $2, $3, 'policy.update', 'accepted', $4::jsonb, $5::jsonb, $6, now())
        `,
        [
          makeId('aud'),
          body.agentId,
          auth.session.sessionId,
          JSON.stringify({ mode: body.mode, approvalMode: body.approvalMode }),
          JSON.stringify({
            maxTradeUsd: body.maxTradeUsd,
            maxDailyUsd: body.maxDailyUsd,
            allowedTokens: body.allowedTokens,
            outboundTransfersEnabled,
            outboundMode,
            outboundWhitelistAddresses,
            snapshotId
          }),
          req.headers.get('user-agent')
        ]
      );
    });

    return successResponse({ ok: true, snapshotId }, 200, requestId);
  } catch {
    return internalErrorResponse(requestId);
  }
}
