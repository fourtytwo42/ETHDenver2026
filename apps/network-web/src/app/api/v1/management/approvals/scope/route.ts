import type { NextRequest } from 'next/server';

import { errorResponse } from '@/lib/errors';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  // Slice 33: pair/global approval scopes are deprecated in the active product surface.
  // Approval is now policy-driven (Global Approval + per-token preapproval toggles), while trade-level approve/reject remains.
  return errorResponse(
    410,
    {
      code: 'policy_denied',
      message: 'Legacy approval scopes are deprecated. Use Global Approval and token preapproval toggles in Policy Controls instead.',
      actionHint: 'Open the agent management page and update policy (Global Approval or token preapprovals), then retry.'
    },
    requestId
  );
}
