import type { NextRequest } from 'next/server';

import { requireAgentAuth } from '@/lib/agent-auth';
import { withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { ensureIdempotency, storeIdempotencyResponse } from '@/lib/idempotency';
import { makeId } from '@/lib/ids';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type RegisterRequest = {
  schemaVersion: number;
  agentId: string;
  agentName: string;
  runtimePlatform: 'windows' | 'linux' | 'macos';
  wallets: Array<{
    chainKey: string;
    address: string;
  }>;
};

async function upsertWallets(client: { query: (text: string, values: unknown[]) => Promise<unknown> }, body: RegisterRequest): Promise<void> {
  for (const wallet of body.wallets) {
    await client.query(
      `
      insert into agent_wallets (
        wallet_id, agent_id, chain_key, address, custody, created_at, updated_at
      ) values ($1, $2, $3, $4, 'agent_local', now(), now())
      on conflict (agent_id, chain_key)
      do update set
        address = excluded.address,
        updated_at = now()
      `,
      [makeId('wlt'), body.agentId, wallet.chainKey, wallet.address]
    );
  }
}

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<RegisterRequest>('agent-register-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Register payload does not match schema.',
          actionHint: 'Ensure required fields and wallet address formats are valid.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;

    const auth = requireAgentAuth(req, body.agentId, requestId);
    if (!auth.ok) {
      return auth.response;
    }

    const idempotency = await ensureIdempotency(req, 'agent_register', body.agentId, body, requestId);
    if (!idempotency.ok) {
      return idempotency.response;
    }

    if (idempotency.ctx.replayResponse) {
      return successResponse(idempotency.ctx.replayResponse.body, idempotency.ctx.replayResponse.status, requestId);
    }

    await withTransaction(async (client) => {
      await client.query(
        `
        insert into agents (
          agent_id, agent_name, runtime_platform, public_status, openclaw_metadata, created_at, updated_at
        ) values ($1, $2, $3, 'offline', '{}'::jsonb, now(), now())
        on conflict (agent_id)
        do update set
          agent_name = excluded.agent_name,
          runtime_platform = excluded.runtime_platform,
          updated_at = now()
        `,
        [body.agentId, body.agentName, body.runtimePlatform]
      );

      await upsertWallets(client, body);

      await client.query(
        `
        insert into agent_events (event_id, agent_id, event_type, payload, created_at)
        values ($1, $2, 'policy_changed', $3::jsonb, now())
        `,
        [makeId('evt'), body.agentId, JSON.stringify({ source: 'register', schemaVersion: body.schemaVersion })]
      );
    });

    const responseBody = {
      ok: true,
      agentId: body.agentId,
      agentName: body.agentName,
      wallets: body.wallets
    };

    await storeIdempotencyResponse(idempotency.ctx, 200, responseBody);
    return successResponse(responseBody, 200, requestId);
  } catch (error) {
    const maybeCode = (error as { code?: string }).code;
    if (maybeCode === '23505') {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Agent registration violates a uniqueness constraint.',
          actionHint: 'Use a unique agent name and wallet chain mapping.',
          details: { databaseCode: maybeCode }
        },
        requestId
      );
    }

    return internalErrorResponse(requestId);
  }
}
