'use client';

import Link from 'next/link';
import { useEffect, useMemo, useState } from 'react';

import { ModeBadge } from '@/components/mode-badge';
import { PublicStatusBadge } from '@/components/public-status-badge';
import { formatUtc, isStale } from '@/lib/public-format';
import { PUBLIC_STATUSES, isPublicStatus, type PublicStatus } from '@/lib/public-types';

type AgentRow = {
  agent_id: string;
  agent_name: string;
  runtime_platform: string;
  public_status: string;
  created_at: string;
  last_activity_at: string | null;
};

type AgentsPayload = {
  ok: boolean;
  page: number;
  pageSize: number;
  total: number;
  items: AgentRow[];
};

export default function AgentsDirectoryPage() {
  const [query, setQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [status, setStatus] = useState<'all' | PublicStatus>('all');
  const [mode, setMode] = useState<'mock' | 'real'>('mock');
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
        mode,
        chain: 'all',
        page: String(page),
        pageSize: '20',
        sort,
        includeDeactivated: String(includeDeactivated)
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
  }, [debouncedQuery, mode, page, sort, status, includeDeactivated]);

  const totalPages = useMemo(() => {
    if (!payload) {
      return 1;
    }

    return Math.max(1, Math.ceil(payload.total / payload.pageSize));
  }, [payload]);

  return (
    <div>
      <h1 className="section-title">Agents Directory</h1>
      <p className="muted">Search by name, agent id, or wallet substring. Timestamps are UTC.</p>

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
          <span className="muted">Mode </span>
          <select value={mode} onChange={(event) => setMode(event.target.value as 'mock' | 'real')}>
            <option value="mock">mock</option>
            <option value="real">real</option>
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
        <div className="muted" style={{ marginBottom: '0.7rem' }}>
          Context: <ModeBadge mode={mode} />
        </div>

        {error ? <p className="warning-banner">{error}</p> : null}
        {!payload ? <p className="muted">Loading agents...</p> : null}
        {payload && payload.items.length === 0 ? <p className="muted">No agents match the current filters.</p> : null}

        {payload && payload.items.length > 0 ? (
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
                  <tr key={item.agent_id}>
                    <td>
                      <Link href={`/agents/${item.agent_id}`}>{item.agent_name}</Link>
                    </td>
                    <td>{isPublicStatus(item.public_status) ? <PublicStatusBadge status={item.public_status} /> : item.public_status}</td>
                    <td>{item.runtime_platform}</td>
                    <td>
                      {formatUtc(item.last_activity_at)}
                      {isStale(item.last_activity_at, 60) ? <div className="stale">sync delay</div> : null}
                    </td>
                    <td>{formatUtc(item.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
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
