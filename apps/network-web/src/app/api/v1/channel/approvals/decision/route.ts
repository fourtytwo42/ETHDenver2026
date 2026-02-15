import type { NextRequest } from 'next/server';

import { dbQuery, withTransaction } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { makeId } from '@/lib/ids';
import { getChainConfig } from '@/lib/chains';
import { constantTimeEqualHex, hashApprovalChannelSecret } from '@/lib/approval-channel-secret';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type ChannelApprovalDecisionRequest = {
  agentId?: string | null;
  tradeId: string;
  chainKey: string;
  decision: 'approve';
  source: {
    channel: 'telegram';
    to: string;
    messageId: string;
    senderId: string;
  };
};

function parseBearerSecret(req: NextRequest): string | null {
  const header = req.headers.get('authorization') ?? '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return null;
  }
  const token = (match[1] ?? '').trim();
  if (!token) {
    return null;
  }
  return token;
}

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const bearer = parseBearerSecret(req);
    if (!bearer) {
      return errorResponse(
        401,
        {
          code: 'auth_invalid',
          message: 'Missing Authorization Bearer secret.',
          actionHint: 'Provide Authorization: Bearer xappr_...'
        },
        requestId
      );
    }

    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<ChannelApprovalDecisionRequest>('channel-approval-decision-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Channel approval decision payload does not match schema.',
          actionHint: 'Provide tradeId, chainKey, decision, and source fields.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;
    if (!getChainConfig(body.chainKey)) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Invalid chainKey value.',
          actionHint: 'Use a supported chain key (for example base_sepolia).',
          details: { chainKey: body.chainKey }
        },
        requestId
      );
    }

    // Derive agentId from tradeId if omitted, and validate chainKey matches.
    const tradeLookup = await dbQuery<{ agent_id: string; chain_key: string; status: string }>(
      `
      select agent_id, chain_key, status
      from trades
      where trade_id = $1
      limit 1
      `,
      [body.tradeId]
    );
    if (tradeLookup.rowCount === 0) {
      return errorResponse(
        404,
        {
          code: 'payload_invalid',
          message: 'Trade was not found.',
          actionHint: 'Verify tradeId and retry.'
        },
        requestId
      );
    }

    const tradeRow = tradeLookup.rows[0];
    const agentId = (body.agentId ?? '').trim() || tradeRow.agent_id;
    if (agentId !== tradeRow.agent_id) {
      return errorResponse(
        401,
        {
          code: 'auth_invalid',
          message: 'Trade does not belong to the provided agentId.',
          actionHint: 'Provide the correct agentId or omit it to derive from tradeId.'
        },
        requestId
      );
    }
    if (tradeRow.chain_key !== body.chainKey) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Trade chain does not match request chainKey.',
          actionHint: 'Provide the matching chainKey.',
          details: { tradeChainKey: tradeRow.chain_key, chainKey: body.chainKey }
        },
        requestId
      );
    }

    const expected = await dbQuery<{ enabled: boolean; secret_hash: string | null }>(
      `
      select enabled, secret_hash
      from agent_chain_approval_channels
      where agent_id = $1
        and chain_key = $2
        and channel = 'telegram'
      limit 1
      `,
      [agentId, body.chainKey]
    );

    if ((expected.rowCount ?? 0) === 0 || !expected.rows[0].enabled) {
      return errorResponse(
        400,
        {
          code: 'policy_denied',
          message: `Telegram approvals are not enabled for chain '${body.chainKey}'.`,
          actionHint: 'Enable Telegram approvals in the agent management page and retry.',
          details: { agentId, chainKey: body.chainKey, channel: 'telegram', enabled: false }
        },
        requestId
      );
    }

    const storedHash = expected.rows[0].secret_hash;
    if (!storedHash) {
      return errorResponse(
        401,
        {
          code: 'auth_invalid',
          message: 'Approval channel secret is not configured.',
          actionHint: 'Disable and re-enable Telegram approvals to rotate a fresh secret.'
        },
        requestId
      );
    }

    const computed = hashApprovalChannelSecret(bearer);
    if (!constantTimeEqualHex(computed, storedHash)) {
      return errorResponse(
        401,
        {
          code: 'auth_invalid',
          message: 'Invalid approval secret.',
          actionHint: 'Verify the secret configured in OpenClaw and retry.'
        },
        requestId
      );
    }

    const result = await withTransaction(async (client) => {
      const current = await client.query<{ status: string }>(
        `
        select status
        from trades
        where trade_id = $1
          and agent_id = $2
          and chain_key = $3
        limit 1
        `,
        [body.tradeId, agentId, body.chainKey]
      );
      if (current.rowCount === 0) {
        return { ok: false as const, kind: 'missing' as const };
      }

      const status = current.rows[0].status;
      if (status === 'approved') {
        return { ok: true as const, transitioned: false as const, status: 'approved' as const };
      }

      if (status !== 'approval_pending') {
        return { ok: false as const, kind: 'not_actionable' as const, status };
      }

      await client.query(
        `
        update trades
        set status = 'approved',
            updated_at = now()
        where trade_id = $1
        `,
        [body.tradeId]
      );

      await client.query(
        `
        insert into agent_events (event_id, agent_id, trade_id, event_type, payload, created_at)
        values ($1, $2, $3, 'trade_approved', $4::jsonb, now())
        `,
        [
          makeId('evt'),
          agentId,
          body.tradeId,
          JSON.stringify({
            source: 'telegram',
            senderId: body.source.senderId,
            to: body.source.to,
            messageId: body.source.messageId
          })
        ]
      );

      return { ok: true as const, transitioned: true as const, status: 'approved' as const };
    });

    if (!result.ok) {
      if (result.kind === 'missing') {
        return errorResponse(
          404,
          {
            code: 'payload_invalid',
            message: 'Trade was not found.',
            actionHint: 'Verify tradeId and retry.'
          },
          requestId
        );
      }

      return errorResponse(
        409,
        {
          code: 'not_actionable',
          message: 'Trade cannot be approved from its current status.',
          actionHint: 'Approve only pending trades.',
          details: { tradeId: body.tradeId, status: result.status }
        },
        requestId
      );
    }

    return successResponse(
      {
        ok: true,
        tradeId: body.tradeId,
        chainKey: body.chainKey,
        status: result.status
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}

