import { getEnv } from '@/lib/env';
import { getRedisClient } from '@/lib/redis';

const INCIDENT_LIST_KEY = 'xclaw:ops:incidents:v1';
const LAST_STATUS_KEY = 'xclaw:ops:last-status:v1';
const MAX_INCIDENTS = 50;

export type OverallHealthStatus = 'healthy' | 'degraded' | 'offline';

export type IncidentCategory =
  | 'api_error_rate'
  | 'rpc_failure_rate'
  | 'queue_backlog'
  | 'heartbeat_miss'
  | 'dependency_outage';

export type IncidentEntry = {
  id: string;
  atUtc: string;
  category: IncidentCategory;
  severity: 'info' | 'warning' | 'critical';
  summary: string;
  details?: string;
};

type SnapshotInput = {
  generatedAtUtc: string;
  overallStatus: OverallHealthStatus;
  dependencyStatuses: Array<'healthy' | 'degraded' | 'offline'>;
  providerUnhealthyCount: number;
  heartbeatMisses: number;
  queueDepth: number;
};

function randomId(): string {
  return `inc_${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36).slice(-4)}`;
}

export function logOps(event: string, payload: Record<string, unknown>): void {
  const body = {
    ts: new Date().toISOString(),
    source: 'xclaw-ops',
    event,
    ...payload
  };
  console.log(JSON.stringify(body));
}

function inferPrimaryCategory(snapshot: SnapshotInput): IncidentCategory {
  if (snapshot.dependencyStatuses.some((status) => status === 'offline')) {
    return 'dependency_outage';
  }
  if (snapshot.providerUnhealthyCount > 0) {
    return 'rpc_failure_rate';
  }
  if (snapshot.heartbeatMisses > 0) {
    return 'heartbeat_miss';
  }
  if (snapshot.queueDepth > 100) {
    return 'queue_backlog';
  }
  return 'api_error_rate';
}

function buildSummary(snapshot: SnapshotInput): string {
  if (snapshot.overallStatus === 'healthy') {
    return 'System health recovered to healthy.';
  }

  if (snapshot.dependencyStatuses.some((status) => status === 'offline')) {
    return 'Core dependency outage detected.';
  }

  if (snapshot.providerUnhealthyCount > 0) {
    return 'RPC provider health degraded.';
  }

  if (snapshot.heartbeatMisses > 0) {
    return 'Heartbeat misses detected past offline threshold.';
  }

  return 'System degraded.';
}

function buildDetail(snapshot: SnapshotInput): string {
  return `providersUnhealthy=${snapshot.providerUnhealthyCount}, heartbeatMisses=${snapshot.heartbeatMisses}, queueDepth=${snapshot.queueDepth}`;
}

async function appendIncident(entry: IncidentEntry): Promise<void> {
  const redis = await getRedisClient();
  await redis.lPush(INCIDENT_LIST_KEY, JSON.stringify(entry));
  await redis.lTrim(INCIDENT_LIST_KEY, 0, MAX_INCIDENTS - 1);
}

async function emitWebhook(
  transition: { from: OverallHealthStatus | null; to: OverallHealthStatus },
  snapshot: SnapshotInput,
  incident: IncidentEntry
): Promise<void> {
  const env = getEnv();
  if (!env.opsAlertWebhookUrl) {
    return;
  }

  const timeoutMs = env.opsAlertWebhookTimeoutMs;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    await fetch(env.opsAlertWebhookUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        source: 'xclaw',
        event: 'health_transition',
        generatedAtUtc: snapshot.generatedAtUtc,
        transition,
        incident
      }),
      signal: controller.signal
    });
  } catch {
    logOps('alert_webhook_failed', {
      to: transition.to,
      category: incident.category
    });
  } finally {
    clearTimeout(timer);
  }
}

export async function getRecentIncidents(limit = 20): Promise<IncidentEntry[]> {
  try {
    const redis = await getRedisClient();
    const rows = await redis.lRange(INCIDENT_LIST_KEY, 0, Math.max(0, limit - 1));
    return rows
      .map((raw) => {
        try {
          return JSON.parse(raw) as IncidentEntry;
        } catch {
          return null;
        }
      })
      .filter((row): row is IncidentEntry => row !== null);
  } catch {
    return [];
  }
}

export async function publishStatusSnapshot(snapshot: SnapshotInput): Promise<void> {
  logOps('status_snapshot', {
    overallStatus: snapshot.overallStatus,
    providerUnhealthyCount: snapshot.providerUnhealthyCount,
    heartbeatMisses: snapshot.heartbeatMisses,
    queueDepth: snapshot.queueDepth
  });

  try {
    const redis = await getRedisClient();
    const previous = (await redis.get(LAST_STATUS_KEY)) as OverallHealthStatus | null;

    if (previous === snapshot.overallStatus) {
      return;
    }

    await redis.set(LAST_STATUS_KEY, snapshot.overallStatus);

    const incident: IncidentEntry = {
      id: randomId(),
      atUtc: snapshot.generatedAtUtc,
      category: inferPrimaryCategory(snapshot),
      severity: snapshot.overallStatus === 'offline' ? 'critical' : snapshot.overallStatus === 'degraded' ? 'warning' : 'info',
      summary: buildSummary(snapshot),
      details: buildDetail(snapshot)
    };

    await appendIncident(incident);
    await emitWebhook({ from: previous, to: snapshot.overallStatus }, snapshot, incident);

    logOps('status_transition', {
      from: previous,
      to: snapshot.overallStatus,
      category: incident.category
    });
  } catch {
    // Best effort only.
  }
}
