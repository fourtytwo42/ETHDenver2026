'use client';

import { useEffect, useMemo, useState } from 'react';
import { useParams, useRouter, useSearchParams } from 'next/navigation';

import { ModeBadge } from '@/components/mode-badge';
import { PublicStatusBadge } from '@/components/public-status-badge';
import { formatNumber, formatPercent, formatUsd, formatUtc, isStale, shortenAddress } from '@/lib/public-format';
import { isPublicStatus } from '@/lib/public-types';

type BootstrapState =
  | { phase: 'bootstrapping' }
  | { phase: 'error'; message: string }
  | { phase: 'ready' };

type AgentProfilePayload = {
  ok: boolean;
  agent: {
    agent_id: string;
    agent_name: string;
    description: string | null;
    owner_label: string | null;
    runtime_platform: string;
    public_status: string;
    created_at: string;
    updated_at: string;
    last_activity_at: string | null;
  };
  wallets: Array<{
    chain_key: string;
    address: string;
    custody: string;
  }>;
  latestMetrics:
    | {
        window: string;
        pnl_usd: string | null;
        return_pct: string | null;
        volume_usd: string | null;
        trades_count: number;
        followers_count: number;
        created_at: string;
      }
    | null;
};

type TradePayload = {
  ok: boolean;
  items: Array<{
    trade_id: string;
    chain_key: string;
    is_mock: boolean;
    status: string;
    token_in: string;
    token_out: string;
    pair: string;
    amount_in: string | null;
    amount_out: string | null;
    reason: string | null;
    reason_code: string | null;
    reason_message: string | null;
    tx_hash: string | null;
    mock_receipt_id: string | null;
    executed_at: string | null;
    created_at: string;
  }>;
};

type ActivityPayload = {
  ok: boolean;
  items: Array<{
    event_id: string;
    agent_id: string;
    event_type: string;
    created_at: string;
  }>;
};

async function bootstrapSession(agentId: string, token: string): Promise<{ ok: true } | { ok: false; message: string }> {
  const response = await fetch('/api/v1/management/session/bootstrap', {
    method: 'POST',
    headers: {
      'content-type': 'application/json'
    },
    credentials: 'same-origin',
    body: JSON.stringify({ agentId, token })
  });

  if (!response.ok) {
    let message = 'Bootstrap failed. Verify token and retry.';
    try {
      const payload = (await response.json()) as { message?: string };
      if (payload?.message) {
        message = payload.message;
      }
    } catch {
      // keep fallback message
    }
    return { ok: false, message };
  }

  return { ok: true };
}

export default function AgentPublicProfilePage() {
  const params = useParams<{ agentId: string }>();
  const router = useRouter();
  const searchParams = useSearchParams();
  const agentId = params.agentId;

  const [bootstrapState, setBootstrapState] = useState<BootstrapState>({ phase: 'ready' });
  const [profile, setProfile] = useState<AgentProfilePayload | null>(null);
  const [trades, setTrades] = useState<TradePayload['items'] | null>(null);
  const [activity, setActivity] = useState<ActivityPayload['items'] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!agentId) {
      return;
    }

    const token = searchParams.get('token');
    if (!token) {
      setBootstrapState({ phase: 'ready' });
      return;
    }

    setBootstrapState({ phase: 'bootstrapping' });
    void bootstrapSession(agentId, token).then((result) => {
      if (!result.ok) {
        setBootstrapState({ phase: 'error', message: result.message });
        return;
      }

      router.replace(`/agents/${agentId}`);
      setBootstrapState({ phase: 'ready' });
    });
  }, [agentId, router, searchParams]);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      if (!agentId || bootstrapState.phase !== 'ready') {
        return;
      }

      setError(null);
      try {
        const [profileRes, tradesRes, activityRes] = await Promise.all([
          fetch(`/api/v1/public/agents/${agentId}`, { cache: 'no-store' }),
          fetch(`/api/v1/public/agents/${agentId}/trades?limit=20`, { cache: 'no-store' }),
          fetch('/api/v1/public/activity?limit=100', { cache: 'no-store' })
        ]);

        if (!profileRes.ok || !tradesRes.ok || !activityRes.ok) {
          throw new Error('Failed to load public profile data.');
        }

        const profilePayload = (await profileRes.json()) as AgentProfilePayload;
        const tradesPayload = (await tradesRes.json()) as TradePayload;
        const activityPayload = (await activityRes.json()) as ActivityPayload;

        if (!cancelled) {
          setProfile(profilePayload);
          setTrades(tradesPayload.items);
          setActivity(activityPayload.items.filter((event) => event.agent_id === agentId).slice(0, 12));
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError instanceof Error ? loadError.message : 'Failed to load public profile data.');
        }
      }
    }

    void load();

    return () => {
      cancelled = true;
    };
  }, [agentId, bootstrapState.phase]);

  const mixedMode = useMemo(() => {
    const tradeRows = trades ?? [];
    const hasReal = tradeRows.some((trade) => !trade.is_mock);
    return hasReal ? 'real' : 'mock';
  }, [trades]);

  if (bootstrapState.phase === 'bootstrapping') {
    return <main className="panel">Validating management token...</main>;
  }

  if (bootstrapState.phase === 'error') {
    return (
      <main className="panel">
        <h1 className="section-title">Management bootstrap failed</h1>
        <p>{bootstrapState.message}</p>
      </main>
    );
  }

  return (
    <div className="profile-grid">
      {error ? <p className="warning-banner">{error}</p> : null}

      <section className="panel">
        <h1 className="section-title">Agent Profile</h1>
        {!profile ? <p className="muted">Loading agent profile...</p> : null}

        {profile ? (
          <>
            <div className="identity-row">
              <strong>{profile.agent.agent_name}</strong>
              {isPublicStatus(profile.agent.public_status) ? <PublicStatusBadge status={profile.agent.public_status} /> : profile.agent.public_status}
              <ModeBadge mode={mixedMode} />
              <span className="muted">{profile.agent.runtime_platform}</span>
              <span className="muted">Last activity: {formatUtc(profile.agent.last_activity_at)} UTC</span>
            </div>
            {isStale(profile.agent.last_activity_at, 60) ? <p className="stale">This agent is in sync-delay or offline threshold window.</p> : null}
            {profile.agent.description ? <p style={{ marginTop: '0.8rem' }}>{profile.agent.description}</p> : null}

            <div className="toolbar" style={{ marginTop: '0.8rem' }}>
              {(profile.wallets ?? []).map((wallet) => (
                <span className="chain-chip" key={`${wallet.chain_key}-${wallet.address}`}>
                  {wallet.chain_key}: {shortenAddress(wallet.address)}
                </span>
              ))}
            </div>
          </>
        ) : null}
      </section>

      <section className="kpi-grid">
        <article className="panel">
          <div className="muted">PnL</div>
          <div className="kpi-value">{formatUsd(profile?.latestMetrics?.pnl_usd ?? null)}</div>
        </article>
        <article className="panel">
          <div className="muted">Return</div>
          <div className="kpi-value">{formatPercent(profile?.latestMetrics?.return_pct ?? null)}</div>
        </article>
        <article className="panel">
          <div className="muted">Volume</div>
          <div className="kpi-value">{formatUsd(profile?.latestMetrics?.volume_usd ?? null)}</div>
        </article>
        <article className="panel">
          <div className="muted">Trades / Followers</div>
          <div className="kpi-value">
            {formatNumber(profile?.latestMetrics?.trades_count ?? null)} / {formatNumber(profile?.latestMetrics?.followers_count ?? null)}
          </div>
        </article>
      </section>

      <section className="panel">
        <h2 className="section-title">Trades</h2>
        {!trades ? <p className="muted">Loading trades...</p> : null}
        {trades && trades.length === 0 ? <p className="muted">No trades found for this agent.</p> : null}
        {trades && trades.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Mode</th>
                  <th>Pair</th>
                  <th>Status</th>
                  <th>Execution ID</th>
                  <th>Reason</th>
                  <th>Created (UTC)</th>
                </tr>
              </thead>
              <tbody>
                {trades.map((trade) => (
                  <tr key={trade.trade_id}>
                    <td>{trade.is_mock ? <ModeBadge mode="mock" /> : <ModeBadge mode="real" />}</td>
                    <td>{trade.pair}</td>
                    <td>{trade.status}</td>
                    <td>{trade.is_mock ? trade.mock_receipt_id ?? '-' : trade.tx_hash ?? '-'}</td>
                    <td>{trade.reason_code ?? trade.reason_message ?? trade.reason ?? '-'}</td>
                    <td>{formatUtc(trade.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>

      <section className="panel">
        <h2 className="section-title">Activity Timeline</h2>
        {!activity ? <p className="muted">Loading activity...</p> : null}
        {activity && activity.length === 0 ? <p className="muted">No activity events yet.</p> : null}
        {activity && activity.length > 0 ? (
          <div className="activity-list">
            {activity.map((event) => (
              <article className="activity-item" key={event.event_id}>
                <div>
                  <strong>{event.event_type}</strong>
                </div>
                <div className="muted">{formatUtc(event.created_at)} UTC</div>
              </article>
            ))}
          </div>
        ) : null}
      </section>
    </div>
  );
}
