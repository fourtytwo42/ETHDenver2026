'use client';

import { useEffect, useState } from 'react';

import { formatUtc } from '@/lib/public-format';

type StatusPayload = {
  ok: boolean;
  requestId: string;
  generatedAtUtc: string;
  overallStatus: 'healthy' | 'degraded' | 'offline';
  dependencies: Array<{
    name: 'api' | 'db' | 'redis';
    status: 'healthy' | 'degraded' | 'offline';
    latencyMs: number | null;
    checkedAtUtc: string;
    detail?: string;
  }>;
  providers: Array<{
    chainKey: string;
    provider: 'primary' | 'fallback';
    status: 'healthy' | 'degraded';
    latencyMs: number | null;
    checkedAtUtc: string;
    detail?: string;
  }>;
  heartbeat: {
    totalAgents: number;
    activeAgents: number;
    offlineAgents: number;
    degradedAgents: number;
    heartbeatMisses: number;
  };
  queues: {
    copyIntentPending: number;
    approvalPendingTrades: number;
    totalDepth: number;
  };
  incidents: Array<{
    id: string;
    atUtc: string;
    category: string;
    severity: 'info' | 'warning' | 'critical';
    summary: string;
    details?: string;
  }>;
};

function statusTone(status: string): string {
  if (status === 'healthy') {
    return 'status-active';
  }
  if (status === 'degraded') {
    return 'status-degraded';
  }
  return 'status-offline';
}

export default function StatusPage() {
  const [data, setData] = useState<StatusPayload | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        setError(null);
        const res = await fetch('/api/status', { cache: 'no-store' });
        if (!res.ok) {
          throw new Error('Status request failed.');
        }
        const payload = (await res.json()) as StatusPayload;
        if (!cancelled) {
          setData(payload);
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError instanceof Error ? loadError.message : 'Failed to load status.');
        }
      }
    }

    void load();
    const interval = setInterval(() => {
      void load();
    }, 15000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return (
    <div>
      <h1 className="section-title">Public Status</h1>
      <p className="muted">Public-safe diagnostics for API, data dependencies, and chain provider health.</p>

      {error ? <p className="warning-banner">{error}</p> : null}

      <section className="panel status-overview">
        <div>
          <div className="muted">Overall status</div>
          <div className={`kpi-value ${statusTone(data?.overallStatus ?? 'offline')}`}>{data?.overallStatus ?? 'loading...'}</div>
        </div>
        <div>
          <div className="muted">Last updated (UTC)</div>
          <div>{data ? formatUtc(data.generatedAtUtc) : '...'}</div>
        </div>
        <div>
          <div className="muted">Request ID</div>
          <code>{data?.requestId ?? '...'}</code>
        </div>
      </section>

      <section className="panel">
        <h2 className="section-title">Dependency Health</h2>
        <div className="status-grid">
          {(data?.dependencies ?? []).map((dep) => (
            <article key={dep.name} className="management-card">
              <h3>{dep.name.toUpperCase()}</h3>
              <p className={statusTone(dep.status)}>{dep.status}</p>
              <p className="muted">Latency: {dep.latencyMs === null ? 'n/a' : `${dep.latencyMs}ms`}</p>
              <p className="muted">Checked: {formatUtc(dep.checkedAtUtc)} UTC</p>
              {dep.detail ? <p className="muted">{dep.detail}</p> : null}
            </article>
          ))}
        </div>
      </section>

      <section className="panel">
        <h2 className="section-title">Chain Provider Health</h2>
        <div className="status-grid">
          {(data?.providers ?? []).map((provider) => (
            <article key={`${provider.chainKey}_${provider.provider}`} className="management-card">
              <h3>{provider.chainKey}</h3>
              <p className="muted">Provider: {provider.provider}</p>
              <p className={statusTone(provider.status)}>{provider.status}</p>
              <p className="muted">Latency: {provider.latencyMs === null ? 'n/a' : `${provider.latencyMs}ms`}</p>
              <p className="muted">Checked: {formatUtc(provider.checkedAtUtc)} UTC</p>
              {provider.detail ? <p className="muted">{provider.detail}</p> : null}
            </article>
          ))}
        </div>
      </section>

      <section className="panel">
        <h2 className="section-title">Heartbeat and Queue Signals</h2>
        <div className="status-grid">
          <article className="management-card">
            <h3>Agents</h3>
            <p className="muted">Total: {data?.heartbeat.totalAgents ?? 0}</p>
            <p className="muted">Active: {data?.heartbeat.activeAgents ?? 0}</p>
            <p className="muted">Offline: {data?.heartbeat.offlineAgents ?? 0}</p>
            <p className="muted">Degraded: {data?.heartbeat.degradedAgents ?? 0}</p>
            <p className="muted">Heartbeat misses: {data?.heartbeat.heartbeatMisses ?? 0}</p>
          </article>
          <article className="management-card">
            <h3>Queues</h3>
            <p className="muted">Copy intent pending: {data?.queues.copyIntentPending ?? 0}</p>
            <p className="muted">Approval pending trades: {data?.queues.approvalPendingTrades ?? 0}</p>
            <p className="muted">Total depth: {data?.queues.totalDepth ?? 0}</p>
          </article>
        </div>
      </section>

      <section className="panel">
        <h2 className="section-title">Incident Timeline</h2>
        {(data?.incidents ?? []).length === 0 ? <p className="muted">No incidents recorded yet.</p> : null}
        <div className="activity-list">
          {(data?.incidents ?? []).map((incident) => (
            <article key={incident.id} className="activity-item">
              <div><strong>{incident.summary}</strong></div>
              <div className="muted">Category: {incident.category}</div>
              <div className="muted">Severity: {incident.severity}</div>
              <div className="muted">{formatUtc(incident.atUtc)} UTC</div>
              {incident.details ? <div className="muted">{incident.details}</div> : null}
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}
