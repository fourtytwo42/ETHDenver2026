import type { NextRequest } from 'next/server';

import { internalErrorResponse, successResponse } from '@/lib/errors';
import { getHealthSnapshot } from '@/lib/ops-health';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

export async function GET(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const snapshot = await getHealthSnapshot();

    return successResponse(
      {
        ok: true,
        requestId,
        generatedAtUtc: snapshot.generatedAtUtc,
        overallStatus: snapshot.overallStatus,
        dependencies: snapshot.dependencies
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
