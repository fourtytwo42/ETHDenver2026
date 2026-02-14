import type { NextRequest } from 'next/server';

import { authenticateAgentByToken } from '@/lib/agent-auth';
import { dbQuery } from '@/lib/db';
import { internalErrorResponse, successResponse } from '@/lib/errors';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

function normalizeAddresses(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const unique = new Set<string>();
  for (const entry of value) {
    if (typeof entry !== 'string') {
      continue;
    }
    const trimmed = entry.trim().toLowerCase();
    if (/^0x[a-f0-9]{40}$/.test(trimmed)) {
      unique.add(trimmed);
    }
  }
  return [...unique];
}

export async function GET(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const auth = authenticateAgentByToken(req, requestId);
    if (!auth.ok) {
      return auth.response;
    }

    const chainKey = req.nextUrl.searchParams.get('chainKey')?.trim() || 'base_sepolia';
    const policy = await dbQuery<{
      outbound_transfers_enabled: boolean;
      outbound_mode: 'disabled' | 'allow_all' | 'whitelist';
      outbound_whitelist_addresses: unknown;
      updated_at: string;
    }>(
      `
      select outbound_transfers_enabled, outbound_mode::text, outbound_whitelist_addresses, updated_at::text
      from agent_transfer_policies
      where agent_id = $1
        and chain_key = $2
      limit 1
      `,
      [auth.agentId, chainKey]
    );

    const row = policy.rows[0];
    const outboundMode = row?.outbound_mode ?? 'disabled';
    const outboundTransfersEnabled = row?.outbound_transfers_enabled ?? false;
    const outboundWhitelistAddresses = normalizeAddresses(row?.outbound_whitelist_addresses ?? []);

    return successResponse(
      {
        ok: true,
        agentId: auth.agentId,
        chainKey,
        outboundTransfersEnabled,
        outboundMode,
        outboundWhitelistAddresses,
        updatedAt: row?.updated_at ?? null
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}

