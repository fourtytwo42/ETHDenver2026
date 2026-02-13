export type AgentApiKeyMap = Record<string, string>;

export type AppEnv = {
  databaseUrl: string;
  redisUrl: string;
  agentApiKeys: AgentApiKeyMap;
  idempotencyTtlSec: number;
};

let cachedEnv: AppEnv | null = null;

function parseAgentApiKeys(raw: string | undefined): AgentApiKeyMap {
  if (!raw) {
    throw new Error('Missing required env: XCLAW_AGENT_API_KEYS');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('Invalid JSON in XCLAW_AGENT_API_KEYS');
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('XCLAW_AGENT_API_KEYS must be a JSON object mapping agentId to apiKey');
  }

  const entries = Object.entries(parsed as Record<string, unknown>);
  if (entries.length === 0) {
    throw new Error('XCLAW_AGENT_API_KEYS must include at least one agent key mapping');
  }

  const map: AgentApiKeyMap = {};
  for (const [agentId, token] of entries) {
    if (!agentId || typeof token !== 'string' || token.length < 8) {
      throw new Error('XCLAW_AGENT_API_KEYS contains invalid mapping values');
    }
    map[agentId] = token;
  }

  return map;
}

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw) {
    return fallback;
  }

  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error('XCLAW_IDEMPOTENCY_TTL_SEC must be a positive integer when provided');
  }
  return parsed;
}

export function getEnv(): AppEnv {
  if (cachedEnv) {
    return cachedEnv;
  }

  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error('Missing required env: DATABASE_URL');
  }

  const redisUrl = process.env.REDIS_URL;
  if (!redisUrl) {
    throw new Error('Missing required env: REDIS_URL');
  }

  cachedEnv = {
    databaseUrl,
    redisUrl,
    agentApiKeys: parseAgentApiKeys(process.env.XCLAW_AGENT_API_KEYS),
    idempotencyTtlSec: parsePositiveInt(process.env.XCLAW_IDEMPOTENCY_TTL_SEC, 24 * 60 * 60)
  };

  return cachedEnv;
}
