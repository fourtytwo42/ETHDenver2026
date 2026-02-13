import { randomBytes } from 'node:crypto';

import type { NextRequest } from 'next/server';

export function getRequestId(req: NextRequest): string {
  const existing = req.headers.get('x-request-id');
  if (existing && existing.trim().length >= 8) {
    return existing.trim();
  }

  return `req_${randomBytes(8).toString('hex')}`;
}
