import { createHmac, timingSafeEqual } from 'node:crypto';

import { requireManagementTokenEncKey } from '@/lib/env';

function getManagementKey(): Buffer {
  const decoded = Buffer.from(requireManagementTokenEncKey(), 'base64');
  if (decoded.length !== 32) {
    throw new Error('XCLAW_MANAGEMENT_TOKEN_ENC_KEY must decode to 32 bytes');
  }
  return decoded;
}

function hmacHex(domain: string, value: string): string {
  const hmac = createHmac('sha256', getManagementKey());
  hmac.update(domain);
  hmac.update(':');
  hmac.update(value);
  return hmac.digest('hex');
}

export function hashApprovalChannelSecret(secret: string): string {
  // Domain-separated hash so this secret cannot be confused with other HMAC uses.
  return hmacHex('approval_channel_secret', secret);
}

export function constantTimeEqualHex(left: string, right: string): boolean {
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}

