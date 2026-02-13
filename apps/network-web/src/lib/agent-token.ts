import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import { getEnv } from '@/lib/env';

const TOKEN_PREFIX = 'xak1';

function resolveSigningKey(): Buffer | null {
  const env = getEnv();
  const raw = (env.agentTokenSigningKey || '').trim();
  if (raw) {
    return Buffer.from(raw, 'utf8');
  }

  const fallback = (env.managementTokenEncKey || '').trim();
  if (!fallback) {
    return null;
  }

  try {
    const decoded = Buffer.from(fallback, 'base64');
    return decoded.length > 0 ? decoded : null;
  } catch {
    return null;
  }
}

function signPayload(payload: string, key: Buffer): string {
  return createHmac('sha256', key).update(payload).digest('base64url');
}

export function issueSignedAgentToken(agentId: string): string | null {
  const key = resolveSigningKey();
  if (!key) {
    return null;
  }

  const nonce = randomBytes(12).toString('base64url');
  const payload = `${agentId}.${nonce}`;
  const signature = signPayload(payload, key);
  return `${TOKEN_PREFIX}.${agentId}.${nonce}.${signature}`;
}

export function verifySignedAgentToken(token: string): { ok: true; agentId: string } | { ok: false } {
  const key = resolveSigningKey();
  if (!key) {
    return { ok: false };
  }

  const parts = token.split('.');
  if (parts.length !== 4 || parts[0] !== TOKEN_PREFIX) {
    return { ok: false };
  }

  const [, agentId, nonce, signature] = parts;
  if (!agentId || !nonce || !signature) {
    return { ok: false };
  }

  const payload = `${agentId}.${nonce}`;
  const expected = signPayload(payload, key);
  const expectedBuf = Buffer.from(expected, 'utf8');
  const providedBuf = Buffer.from(signature, 'utf8');
  if (expectedBuf.length !== providedBuf.length) {
    return { ok: false };
  }

  if (!timingSafeEqual(expectedBuf, providedBuf)) {
    return { ok: false };
  }

  return { ok: true, agentId };
}
