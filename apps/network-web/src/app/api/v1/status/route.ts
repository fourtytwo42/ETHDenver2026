import type { NextRequest } from 'next/server';

import { internalErrorResponse, successResponse } from '@/lib/errors';
import { getRecentIncidents, publishStatusSnapshot } from '@/lib/ops-alerts';
import { getStatusSnapshot } from '@/lib/ops-health';
import { enforcePublicReadRateLimit } from '@/lib/rate-limit';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

export async function GET(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const rateLimited = await enforcePublicReadRateLimit(req, requestId);
    if (!rateLimited.ok) {
      return rateLimited.response;
    }

    const snapshot = await getStatusSnapshot();
    await publishStatusSnapshot({
      generatedAtUtc: snapshot.generatedAtUtc,
      overallStatus: snapshot.overallStatus,
      dependencyStatuses: snapshot.dependencies.map((dep) => dep.status),
      providerUnhealthyCount: snapshot.providers.filter((provider) => provider.status !== 'healthy').length,
      heartbeatMisses: snapshot.heartbeat.heartbeatMisses,
      queueDepth: snapshot.queues.totalDepth
    });

    const incidents = await getRecentIncidents(20);

    return successResponse(
      {
        ok: true,
        requestId,
        generatedAtUtc: snapshot.generatedAtUtc,
        overallStatus: snapshot.overallStatus,
        dependencies: snapshot.dependencies,
        providers: snapshot.providers,
        heartbeat: snapshot.heartbeat,
        queues: snapshot.queues,
        incidents
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
