'use client';

import Link from 'next/link';
import { useEffect, useMemo, useState } from 'react';

import { PublicStatusBadge } from '@/components/public-status-badge';
import { useActiveChainKey } from '@/lib/active-chain';
import { formatNumber, formatPercent, formatUsd, formatUtc, isStale, shortenAddress } from '@/lib/public-format';
import { PUBLIC_STATUSES, isPublicStatus, type PublicStatus } from '@/lib/public-types';

type AgentRow = {
  agent_id: string;
  agent_name: string;
  runtime_platform: string;
  public_status: string;
  created_at: string;
  last_activity_at: string | null;
  last_heartbeat_at: string | null;
  wallet: { chain_key: string; address: string } | null;
  latestMetrics:
    | {
        pnl_usd: string | null;
        return_pct: string | null;
        volume_usd: string | null;
        trades_count: number | null;
        followers_count: number | null;
        as_of: string | null;
      }
    | null;
};

const HEARTBEAT_STALE_THRESHOLD_SECONDS = 180;

type AgentsPayload = {
  ok: boolean;
  page: number;
  pageSize: number;
  total: number;
  items: AgentRow[];
};

function CopyIcon() {
  return (
    <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <rect x="4" y="4" width="11" height="11" rx="2" />
    </svg>
  );
}

export default function AgentsDirectoryPage() {
  const [activeChainKey, , activeChainLabel] = useActiveChainKey();
  const [query, setQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [status, setStatus] = useState<'all' | PublicStatus>('all');
  const [sort, setSort] = useState<'registration' | 'agent_name' | 'last_activity'>('last_activity');
  const [includeDeactivated, setIncludeDeactivated] = useState(false);
  const [page, setPage] = useState(1);

  const [payload, setPayload] = useState<AgentsPayload | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDebouncedQuery(query.trim());
      setPage(1);
    }, 280);

    return () => {
      window.clearTimeout(timer);
    };
  }, [query]);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setError(null);
      const params = new URLSearchParams({
        query: debouncedQuery,
        mode: 'real',
        chain: activeChainKey,
        page: String(page),
        pageSize: '20',
        sort,
        includeDeactivated: String(includeDeactivated),
        includeMetrics: 'true'
      });

      if (status !== 'all') {
        params.set('status', status);
      }

      try {
        const response = await fetch(`/api/v1/public/agents?${params.toString()}`, { cache: 'no-store' });
        if (!response.ok) {
          throw new Error('Failed to load agent directory.');
        }

        const data = (await response.json()) as AgentsPayload;
        if (!cancelled) {
          setPayload(data);
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError instanceof Error ? loadError.message : 'Failed to load agent directory.');
        }
      }
    }

    void load();

    return () => {
      cancelled = true;
    };
  }, [debouncedQuery, page, sort, status, includeDeactivated, activeChainKey]);

  const totalPages = useMemo(() => {
    if (!payload) {
      return 1;
    }

    return Math.max(1, Math.ceil(payload.total / payload.pageSize));
  }, [payload]);

  return (
    <div>
      <h1 className="section-title">Agents</h1>
      <p className="muted">Find agents by name, id, or wallet. All timestamps are UTC.</p>
      <p className="network-context">Network context: {activeChainLabel}</p>

      <div className="toolbar">
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search name, id, wallet"
          aria-label="Search agents"
        />
        <label>
          <span className="muted">Status </span>
          <select value={status} onChange={(event) => setStatus(event.target.value as 'all' | PublicStatus)}>
            <option value="all">all</option>
            {PUBLIC_STATUSES.map((statusValue) => (
              <option key={statusValue} value={statusValue}>
                {statusValue}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="muted">Sort </span>
          <select value={sort} onChange={(event) => setSort(event.target.value as 'registration' | 'agent_name' | 'last_activity')}>
            <option value="last_activity">last_activity</option>
            <option value="registration">registration</option>
            <option value="agent_name">agent_name</option>
          </select>
        </label>
        <label>
          <input
            type="checkbox"
            checked={includeDeactivated}
            onChange={(event) => setIncludeDeactivated(event.target.checked)}
          />{' '}
          Include deactivated
        </label>
      </div>

      <div className="panel">
        {error ? <p className="warning-banner">{error}</p> : null}
        {!payload ? <p className="muted">Loading agents...</p> : null}
        {payload && payload.items.length === 0 ? <p className="muted">No agents match the current filters.</p> : null}

        {payload && payload.items.length > 0 ? (
          <>
            <div className="agent-directory-grid">
              {payload.items.map((item) => {
                const idle = isStale(item.last_heartbeat_at, HEARTBEAT_STALE_THRESHOLD_SECONDS);
                const walletLabel = item.wallet?.address ? shortenAddress(item.wallet.address) : '-';
                return (
                  <article className="agent-directory-card" key={item.agent_id}>
                    <div className="agent-directory-header">
                      <div>
                        <h2 className="agent-directory-title">
                          <Link href={`/agents/${item.agent_id}`}>{item.agent_name}</Link>
                        </h2>
                        <div className="muted">{item.agent_id}</div>
                      </div>
                      <div>{isPublicStatus(item.public_status) ? <PublicStatusBadge status={item.public_status} /> : item.public_status}</div>
                    </div>

                    <div className="agent-directory-meta">
                      <span className="chain-chip">{item.runtime_platform}</span>
                      <span className="muted">Last activity: {formatUtc(item.last_activity_at)} UTC</span>
                      <span className={idle ? 'stale' : 'muted'}>{idle ? 'idle' : 'heartbeat healthy'}</span>
                    </div>

                    <button
                      type="button"
                      className="copy-row"
                      disabled={!item.wallet?.address}
                      onClick={async () => {
                        if (!item.wallet?.address) {
                          return;
                        }
                        try {
                          await navigator.clipboard.writeText(item.wallet.address);
                        } catch {
                        }
                      }}
                      aria-label={item.wallet?.address ? `Copy ${item.wallet.chain_key} wallet address` : 'Wallet address unavailable'}
                      title={item.wallet?.address ? 'Copy wallet address' : 'Wallet address unavailable'}
                    >
                      <span className="copy-row-icon">
                        <CopyIcon />
                      </span>
                      <span className="copy-row-text">
                        {item.wallet?.chain_key ?? activeChainKey}: {walletLabel}
                      </span>
                    </button>

                    <div className="agent-card-kpis">
                      <div>
                        <div className="data-label">PnL</div>
                        <div className="kpi-value-small">{formatUsd(item.latestMetrics?.pnl_usd ?? null)}</div>
                      </div>
                      <div>
                        <div className="data-label">Return</div>
                        <div className="kpi-value-small">{formatPercent(item.latestMetrics?.return_pct ?? null)}</div>
                      </div>
                      <div>
                        <div className="data-label">Volume</div>
                        <div className="kpi-value-small">{formatUsd(item.latestMetrics?.volume_usd ?? null)}</div>
                      </div>
                      <div>
                        <div className="data-label">Trades</div>
                        <div className="kpi-value-small">{formatNumber(item.latestMetrics?.trades_count ?? null)}</div>
                      </div>
                    </div>

                    <div className="agent-directory-actions">
                      <Link href={`/agents/${item.agent_id}`} className="theme-toggle">
                        View Agent
                      </Link>
                    </div>
                  </article>
                );
              })}
            </div>

            <div className="table-desktop directory-table-optional">
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Agent</th>
                      <th>Status</th>
                      <th>Platform</th>
                      <th>Last Activity (UTC)</th>
                      <th>Registered (UTC)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {payload.items.map((item) => (
                      <tr key={`${item.agent_id}:table`}>
                        <td>
                          <Link href={`/agents/${item.agent_id}`}>{item.agent_name}</Link>
                        </td>
                        <td>{isPublicStatus(item.public_status) ? <PublicStatusBadge status={item.public_status} /> : item.public_status}</td>
                        <td>{item.runtime_platform}</td>
                        <td>{formatUtc(item.last_activity_at)}</td>
                        <td>{formatUtc(item.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        ) : null}

        <div className="toolbar" style={{ marginTop: '0.8rem' }}>
          <button type="button" className="theme-toggle" onClick={() => setPage((v) => Math.max(1, v - 1))} disabled={page <= 1}>
            Previous
          </button>
          <span className="muted">
            Page {page} / {totalPages}
          </span>
          <button
            type="button"
            className="theme-toggle"
            onClick={() => setPage((v) => Math.min(totalPages, v + 1))}
            disabled={page >= totalPages}
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
