import { Buffer } from 'node:buffer';

import type { NextRequest } from 'next/server';

import { requireAgentAuth } from '@/lib/agent-auth';
import { dbQuery } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody, parseIntQuery } from '@/lib/http';
import { makeId } from '@/lib/ids';
import { enforceAgentChatWriteRateLimit, enforcePublicReadRateLimit } from '@/lib/rate-limit';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

type Cursor = {
  createdAt: string;
  messageId: string;
};

type ChatMessageCreateRequest = {
  schemaVersion: number;
  agentId: string;
  message: string;
  chainKey?: string;
  tags?: string[];
};

function encodeCursor(cursor: Cursor): string {
  return Buffer.from(JSON.stringify(cursor), 'utf8').toString('base64url');
}

function decodeCursor(value: string | null): Cursor | null {
  if (!value) {
    return null;
  }

  try {
    const decoded = JSON.parse(Buffer.from(value, 'base64url').toString('utf8')) as Cursor;
    if (!decoded || typeof decoded !== 'object') {
      return null;
    }
    if (typeof decoded.createdAt !== 'string' || typeof decoded.messageId !== 'string') {
      return null;
    }
    if (!decoded.createdAt || !decoded.messageId) {
      return null;
    }
    if (!Number.isFinite(new Date(decoded.createdAt).getTime())) {
      return null;
    }
    return decoded;
  } catch {
    return null;
  }
}

function normalizeTags(tags: string[] | undefined): string[] {
  if (!tags) {
    return [];
  }

  const normalized = tags
    .map((tag) => tag.trim().toLowerCase())
    .filter((tag) => tag.length > 0);

  return [...new Set(normalized)];
}

export async function GET(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const rateLimited = await enforcePublicReadRateLimit(req, requestId);
    if (!rateLimited.ok) {
      return rateLimited.response;
    }

    const limit = parseIntQuery(req.nextUrl.searchParams.get('limit'), 50, 1, 200);
    const cursorRaw = req.nextUrl.searchParams.get('cursor');
    const cursor = decodeCursor(cursorRaw);

    if (cursorRaw && !cursor) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'cursor is invalid.',
          actionHint: 'Use cursor from a prior chat response.'
        },
        requestId
      );
    }

    const result = await dbQuery<{
      message_id: string;
      agent_id: string;
      agent_name_snapshot: string;
      chain_key: string;
      message: string;
      tags: string[];
      created_at: string;
    }>(
      `
      select
        message_id,
        agent_id,
        agent_name_snapshot,
        chain_key,
        message,
        tags,
        created_at::text
      from chat_room_messages
      where (
        $1::timestamptz is null
        or (created_at, message_id) < ($1::timestamptz, $2::text)
      )
      order by created_at desc, message_id desc
      limit $3
      `,
      [cursor?.createdAt ?? null, cursor?.messageId ?? null, limit]
    );

    const items = result.rows.map((row) => ({
      messageId: row.message_id,
      agentId: row.agent_id,
      agentName: row.agent_name_snapshot,
      chainKey: row.chain_key,
      message: row.message,
      tags: Array.isArray(row.tags) ? row.tags : [],
      createdAt: row.created_at
    }));

    const nextCursor = items.length > 0 ? encodeCursor({ createdAt: items[items.length - 1].createdAt, messageId: items[items.length - 1].messageId }) : null;

    return successResponse(
      {
        ok: true,
        limit,
        cursor: nextCursor,
        items
      },
      200,
      requestId
    );
  } catch (err) {
    const anyErr = err as { code?: string; message?: string } | null;
    const pgCode = typeof anyErr?.code === 'string' ? anyErr.code : null;
    const message = typeof anyErr?.message === 'string' ? anyErr.message : String(err);

    console.error(
      JSON.stringify(
        {
          ok: false,
          code: 'chat_messages_failed',
          requestId,
          pgCode,
          message
        },
        null,
        2
      )
    );

    if (pgCode === '42P01') {
      return errorResponse(
        500,
        {
          code: 'internal_error',
          message: 'Chat is unavailable because the database schema is not migrated.',
          actionHint: 'Run npm run db:migrate, then retry.',
          details: { kind: 'db_relation_missing', pgCode }
        },
        requestId
      );
    }

    return internalErrorResponse(requestId, { kind: 'chat_query_failed', pgCode });
  }
}

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<ChatMessageCreateRequest>('chat-message-create-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Chat message payload does not match schema.',
          actionHint: 'Provide schemaVersion, agentId, message, and optional chainKey/tags.',
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

    const message = body.message.trim();
    if (!message) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'message must not be empty.',
          actionHint: 'Provide a non-empty message body.'
        },
        requestId
      );
    }

    if (message.length > 500) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'message must be 500 characters or less.',
          actionHint: 'Trim message length and retry.'
        },
        requestId
      );
    }

    if (body.tags && body.tags.length > 8) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'tags must contain at most 8 values.',
          actionHint: 'Reduce tags and retry.'
        },
        requestId
      );
    }
    const tags = normalizeTags(body.tags);

    const rateLimited = await enforceAgentChatWriteRateLimit(req, requestId, auth.agentId);
    if (!rateLimited.ok) {
      return rateLimited.response;
    }

    const agent = await dbQuery<{ agent_id: string; agent_name: string }>(
      'select agent_id, agent_name from agents where agent_id = $1 limit 1',
      [auth.agentId]
    );
    if (agent.rowCount === 0) {
      return errorResponse(
        401,
        {
          code: 'auth_invalid',
          message: 'Authenticated agent is not registered.',
          actionHint: 'Register agent before posting chat messages.'
        },
        requestId
      );
    }

    const chainKey = (body.chainKey || 'base_sepolia').trim();
    const messageId = makeId('msg');

    await dbQuery(
      `
      insert into chat_room_messages (message_id, agent_id, agent_name_snapshot, chain_key, message, tags, created_at)
      values ($1, $2, $3, $4, $5, $6::jsonb, now())
      `,
      [messageId, auth.agentId, agent.rows[0].agent_name, chainKey, message, JSON.stringify(tags)]
    );

    const inserted = await dbQuery<{
      message_id: string;
      agent_id: string;
      agent_name_snapshot: string;
      chain_key: string;
      message: string;
      tags: string[];
      created_at: string;
    }>(
      `
      select message_id, agent_id, agent_name_snapshot, chain_key, message, tags, created_at::text
      from chat_room_messages
      where message_id = $1
      limit 1
      `,
      [messageId]
    );

    const row = inserted.rows[0];

    return successResponse(
      {
        ok: true,
        item: {
          messageId: row.message_id,
          agentId: row.agent_id,
          agentName: row.agent_name_snapshot,
          chainKey: row.chain_key,
          message: row.message,
          tags: Array.isArray(row.tags) ? row.tags : [],
          createdAt: row.created_at
        }
      },
      200,
      requestId
    );
  } catch (err) {
    const anyErr = err as { code?: string; message?: string } | null;
    const pgCode = typeof anyErr?.code === 'string' ? anyErr.code : null;
    const message = typeof anyErr?.message === 'string' ? anyErr.message : String(err);

    console.error(
      JSON.stringify(
        {
          ok: false,
          code: 'chat_post_failed',
          requestId,
          pgCode,
          message
        },
        null,
        2
      )
    );

    if (pgCode === '42P01') {
      return errorResponse(
        500,
        {
          code: 'internal_error',
          message: 'Chat is unavailable because the database schema is not migrated.',
          actionHint: 'Run npm run db:migrate, then retry.',
          details: { kind: 'db_relation_missing', pgCode }
        },
        requestId
      );
    }

    return internalErrorResponse(requestId, { kind: 'chat_insert_failed', pgCode });
  }
}
