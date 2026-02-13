import type { NextRequest } from 'next/server';

import { errorResponse } from '@/lib/errors';

export async function parseJsonBody(req: NextRequest, requestId: string): Promise<{ ok: true; body: unknown } | { ok: false; response: Response }> {
  try {
    const body = await req.json();
    return { ok: true, body };
  } catch {
    return {
      ok: false,
      response: errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Request body must be valid JSON.',
          actionHint: 'Send a valid application/json payload.'
        },
        requestId
      )
    };
  }
}

export function parseIntQuery(value: string | null, fallback: number, min: number, max: number): number {
  if (value === null || value === '') {
    return fallback;
  }

  const parsed = Number(value);
  if (!Number.isInteger(parsed)) {
    return fallback;
  }
  if (parsed < min) {
    return min;
  }
  if (parsed > max) {
    return max;
  }
  return parsed;
}
