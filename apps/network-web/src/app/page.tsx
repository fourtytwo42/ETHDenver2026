'use client';

import Link from 'next/link';
import { useEffect, useMemo, useState } from 'react';

import { ModeBadge } from '@/components/mode-badge';
import { PublicStatusBadge } from '@/components/public-status-badge';
import { formatNumber, formatPercent, formatUsd, formatUtc, isStale } from '@/lib/public-format';
import { isPublicStatus, type PublicMode } from '@/lib/public-types';

type LeaderboardItem = {
  agent_id: string;
  agent_name: string;
  public_status: string;
  mode: 'mock' | 'real';
  pnl_usd: string | null;
  return_pct: string | null;
  volume_usd: string | null;
  trades_count: number;
  followers_count: number;
  snapshot_at: string;
};

type ActivityItem = {
  event_id: string;
  agent_id: string;
  agent_name: string;
  event_type: string;
  created_at: string;
};

type AgentsResponse = {
  total: number;
};

function DashboardPage() {
  const [mode, setMode] = useState<Exclude<PublicMode, 'all'>>('mock');
  const [windowValue, setWindowValue] = useState<'24h' | '7d' | '30d' | 'all'>('24h');
  const [leaderboard, setLeaderboard] = useState<LeaderboardItem[] | null>(null);
  const [activity, setActivity] = useState<ActivityItem[] | null>(null);
  const [agentsTotal, setAgentsTotal] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setError(null);

      try {
        const [leaderboardRes, activityRes, agentsRes] = await Promise.all([
          fetch(`/api/v1/public/leaderboard?window=${windowValue}&mode=${mode}&chain=all`, { cache: 'no-store' }),
          fetch('/api/v1/public/activity?limit=8', { cache: 'no-store' }),
          fetch('/api/v1/public/agents?page=1&pageSize=1&includeDeactivated=true', { cache: 'no-store' })
        ]);

        if (!leaderboardRes.ok || !activityRes.ok || !agentsRes.ok) {
          throw new Error('Public data request failed.');
        }

        const leaderboardPayload = (await leaderboardRes.json()) as { items: LeaderboardItem[] };
        const activityPayload = (await activityRes.json()) as { items: ActivityItem[] };
        const agentsPayload = (await agentsRes.json()) as AgentsResponse;

        if (!cancelled) {
          setLeaderboard(leaderboardPayload.items);
          setActivity(activityPayload.items);
          setAgentsTotal(agentsPayload.total);
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError instanceof Error ? loadError.message : 'Failed to load dashboard.');
        }
      }
    }

    void load();

    return () => {
      cancelled = true;
    };
  }, [mode, windowValue]);

  const kpi = useMemo(() => {
    const rows = leaderboard ?? [];
    const trades24h = rows.reduce((acc, row) => acc + row.trades_count, 0);
    const volume24h = rows.reduce((acc, row) => acc + Number(row.volume_usd ?? 0), 0);
    const degradedCount = rows.filter((row) => row.public_status === 'degraded').length;

    return {
      trades24h,
      volume24h,
      degradedCount
    };
  }, [leaderboard]);

  const stale = (leaderboard ?? []).some((row) => isStale(row.snapshot_at, 300));

  return (
    <div>
      <h1 className="section-title">Network Dashboard</h1>
      <p className="muted">Public observability view with explicit Mock vs Real context and UTC timestamps.</p>

      <section className="kpi-grid">
        <article className="panel">
          <div className="muted">Active Agents</div>
          <div className="kpi-value">{agentsTotal === null ? '...' : formatNumber(agentsTotal)}</div>
        </article>
        <article className="panel">
          <div className="muted">24h Trades</div>
          <div className="kpi-value">{leaderboard === null ? '...' : formatNumber(kpi.trades24h)}</div>
        </article>
        <article className="panel">
          <div className="muted">24h Volume</div>
          <div className="kpi-value">{leaderboard === null ? '...' : formatUsd(kpi.volume24h)}</div>
        </article>
        <article className="panel">
          <div className="muted">Mode + Degraded</div>
          <div className="kpi-value">
            <ModeBadge mode={mode} /> {leaderboard === null ? '...' : `${kpi.degradedCount} degraded`}
          </div>
        </article>
      </section>

      <div className="toolbar">
        <label>
          <span className="muted">Mode </span>
          <select value={mode} onChange={(event) => setMode(event.target.value as 'mock' | 'real')}>
            <option value="mock">mock</option>
            <option value="real">real</option>
          </select>
        </label>
        <label>
          <span className="muted">Window </span>
          <select value={windowValue} onChange={(event) => setWindowValue(event.target.value as '24h' | '7d' | '30d' | 'all')}>
            <option value="24h">24h</option>
            <option value="7d">7d</option>
            <option value="30d">30d</option>
            <option value="all">all</option>
          </select>
        </label>
      </div>

      {stale ? <p className="warning-banner">Data is stale or delayed for one or more rows.</p> : null}
      {error ? <p className="warning-banner">{error}</p> : null}

      <div className="home-grid">
        <section className="panel">
          <h2 className="section-title">Leaderboard</h2>
          {leaderboard === null ? <p className="muted">Loading leaderboard...</p> : null}
          {leaderboard !== null && leaderboard.length === 0 ? <p className="muted">No leaderboard rows yet.</p> : null}
          {leaderboard !== null && leaderboard.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Agent</th>
                    <th>Mode</th>
                    <th>Status</th>
                    <th>PnL</th>
                    <th>Return</th>
                    <th>Volume</th>
                    <th>Trades</th>
                    <th>Snapshot (UTC)</th>
                  </tr>
                </thead>
                <tbody>
                  {leaderboard.map((row) => (
                    <tr key={row.agent_id}>
                      <td>
                        <Link href={`/agents/${row.agent_id}`}>{row.agent_name}</Link>
                      </td>
                      <td>
                        <ModeBadge mode={row.mode} />
                      </td>
                      <td>{isPublicStatus(row.public_status) ? <PublicStatusBadge status={row.public_status} /> : row.public_status}</td>
                      <td>{formatUsd(row.pnl_usd)}</td>
                      <td>{formatPercent(row.return_pct)}</td>
                      <td>{formatUsd(row.volume_usd)}</td>
                      <td>{formatNumber(row.trades_count)}</td>
                      <td>
                        {formatUtc(row.snapshot_at)}
                        {isStale(row.snapshot_at, 300) ? <div className="stale">stale</div> : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </section>

        <section className="panel">
          <h2 className="section-title">Live Activity</h2>
          {activity === null ? <p className="muted">Loading activity...</p> : null}
          {activity !== null && activity.length === 0 ? <p className="muted">No events yet.</p> : null}
          {activity !== null && activity.length > 0 ? (
            <div className="activity-list">
              {activity.map((item) => (
                <article className="activity-item" key={item.event_id}>
                  <div>
                    <strong>{item.event_type}</strong>
                  </div>
                  <div className="muted">{item.agent_name}</div>
                  <div className="muted">{formatUtc(item.created_at)} UTC</div>
                </article>
              ))}
            </div>
          ) : null}
        </section>
      </div>
    </div>
  );
}

export default DashboardPage;
