import type { PoolClient } from 'pg';

import { makeId } from '@/lib/ids';
import { getRedisClient } from '@/lib/redis';

export const LEADERBOARD_CACHE_TTL_SEC = 30;
export const LEADERBOARD_CACHE_PREFIX = 'xclaw:leaderboard:v2:';

const METRIC_WINDOWS: Array<{ key: '24h' | '7d' | '30d' | 'all'; ms: number | null }> = [
  { key: '24h', ms: 24 * 60 * 60 * 1000 },
  { key: '7d', ms: 7 * 24 * 60 * 60 * 1000 },
  { key: '30d', ms: 30 * 24 * 60 * 60 * 1000 },
  { key: 'all', ms: null }
];

function asNumber(value: string | null | undefined): number {
  if (!value) {
    return 0;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return 0;
  }
  return parsed;
}

function normalizeAmountForMetrics(value: string | null | undefined): number {
  const parsed = asNumber(value);
  if (!Number.isFinite(parsed)) {
    return 0;
  }
  const abs = Math.abs(parsed);
  // Historical rows may carry wei-scaled values in amount fields.
  // Heuristic: values at trillion+ scale are interpreted as wei and converted to token units.
  if (abs >= 1e12) {
    return parsed / 1e18;
  }
  return parsed;
}

function calcTradePnl(status: string, volumeUsd: number, isMock: boolean): number {
  if (status === 'filled') {
    return volumeUsd * (isMock ? 0.01 : 0.008);
  }
  if (status === 'failed' || status === 'verification_timeout') {
    return -volumeUsd * 0.002;
  }
  return 0;
}

function calcScore(returnPct: number, pnlUsd: number, volumeUsd: number, tradesCount: number, wins: number): number {
  const pnlNormalized = volumeUsd > 0 ? (pnlUsd / volumeUsd) * 100 : 0;
  const consistency = tradesCount > 0 ? wins / tradesCount : 0;
  return returnPct * 0.5 + pnlNormalized * 0.3 + consistency * 0.2;
}

function windowStartIso(windowMs: number | null, nowMs: number): string | null {
  if (windowMs === null) {
    return null;
  }
  return new Date(nowMs - windowMs).toISOString();
}

export async function invalidateLeaderboardCaches(): Promise<void> {
  try {
    const redis = await getRedisClient();
    const keys = await redis.keys(`${LEADERBOARD_CACHE_PREFIX}*`);
    if (keys.length > 0) {
      await redis.del(keys);
    }
  } catch {
    // Best-effort cache invalidation; read path still works from DB.
  }
}

type TradeMetricRow = {
  chain_key: string;
  is_mock: boolean;
  status: string;
  source_trade_id: string | null;
  amount_usd: string | null;
};

async function recomputeForAgent(client: PoolClient, agentId: string): Promise<void> {
  const nowMs = Date.now();

  const followers = await client.query<{ followers_count: string }>(
    `
    select count(*)::text as followers_count
    from copy_subscriptions
    where leader_agent_id = $1
      and enabled = true
    `,
    [agentId]
  );
  const followersCount = Number.parseInt(followers.rows[0]?.followers_count ?? '0', 10);

  const chainRows = await client.query<{ chain_key: string }>(
    `
    select distinct chain_key
    from trades
    where agent_id = $1
    `,
    [agentId]
  );

  const chains = new Set<string>(['all']);
  for (const row of chainRows.rows) {
    if (row.chain_key) {
      chains.add(row.chain_key);
    }
  }

  for (const windowDef of METRIC_WINDOWS) {
    const startIso = windowStartIso(windowDef.ms, nowMs);

    for (const mode of ['mock', 'real'] as const) {
      for (const chainKey of chains) {
        const result = await client.query<TradeMetricRow>(
          `
          select
            t.chain_key,
            t.is_mock,
            t.status,
            t.source_trade_id,
            coalesce(t.amount_out, t.amount_in)::text as amount_usd
          from trades t
          where t.agent_id = $1
            and t.status in ('filled', 'failed', 'verification_timeout')
            and ($2::text = 'all' or t.chain_key = $2)
            and t.is_mock = $3
            and ($4::timestamptz is null or t.created_at >= $4::timestamptz)
          `,
          [agentId, chainKey, mode === 'mock', startIso]
        );

        let pnlUsd = 0;
        let volumeUsd = 0;
        let tradesCount = 0;
        let wins = 0;

        let selfTradesCount = 0;
        let copiedTradesCount = 0;
        let selfVolumeUsd = 0;
        let copiedVolumeUsd = 0;
        let selfPnlUsd = 0;
        let copiedPnlUsd = 0;

        for (const row of result.rows) {
          const amountUsd = Math.abs(normalizeAmountForMetrics(row.amount_usd));
          const tradePnl = calcTradePnl(row.status, amountUsd, row.is_mock);

          volumeUsd += amountUsd;
          pnlUsd += tradePnl;
          tradesCount += 1;
          if (row.status === 'filled') {
            wins += 1;
          }

          if (row.source_trade_id) {
            copiedTradesCount += 1;
            copiedVolumeUsd += amountUsd;
            copiedPnlUsd += tradePnl;
          } else {
            selfTradesCount += 1;
            selfVolumeUsd += amountUsd;
            selfPnlUsd += tradePnl;
          }
        }

        const returnPct = volumeUsd > 0 ? (pnlUsd / volumeUsd) * 100 : 0;
        const winRatePct = tradesCount > 0 ? (wins / tradesCount) * 100 : null;
        const score = calcScore(returnPct, pnlUsd, volumeUsd, tradesCount, wins);

        await client.query(
          `
          delete from performance_snapshots
          where agent_id = $1
            and "window" = $2::performance_window
            and mode = $3::policy_mode
            and chain_key = $4
          `,
          [agentId, windowDef.key, mode, chainKey]
        );

        await client.query(
          `
          insert into performance_snapshots (
            snapshot_id,
            agent_id,
            "window",
            mode,
            chain_key,
            pnl_usd,
            return_pct,
            volume_usd,
            win_rate_pct,
            trades_count,
            followers_count,
            score,
            self_trades_count,
            copied_trades_count,
            self_volume_usd,
            copied_volume_usd,
            self_pnl_usd,
            copied_pnl_usd,
            stale,
            degraded_reason,
            created_at
          ) values (
            $1, $2, $3::performance_window, $4::policy_mode, $5,
            $6, $7, $8, $9, $10, $11,
            $12, $13, $14, $15, $16, $17, $18,
            false, null, now()
          )
          `,
          [
            makeId('psn'),
            agentId,
            windowDef.key,
            mode,
            chainKey,
            pnlUsd,
            returnPct,
            volumeUsd,
            winRatePct,
            tradesCount,
            followersCount,
            score,
            selfTradesCount,
            copiedTradesCount,
            selfVolumeUsd,
            copiedVolumeUsd,
            selfPnlUsd,
            copiedPnlUsd
          ]
        );
      }
    }
  }
}

export async function recomputeMetricsForAgents(client: PoolClient, agentIds: string[]): Promise<void> {
  const uniq = [...new Set(agentIds.filter((value) => value && value.trim().length > 0))];
  for (const agentId of uniq) {
    await recomputeForAgent(client, agentId);
  }
  await invalidateLeaderboardCaches();
}
