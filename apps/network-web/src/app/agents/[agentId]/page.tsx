'use client';

import { useEffect, useMemo, useState } from 'react';
import { useParams, useRouter, useSearchParams } from 'next/navigation';

import { rememberManagedAgent } from '@/components/management-header-controls';
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
  offdexHistory: Array<{
    settlementIntentId: string;
    chainKey: string;
    role: 'maker' | 'taker';
    status: string;
    pairLabel: string;
    escrowContract: string;
    makerFundTxHash: string | null;
    takerFundTxHash: string | null;
    settlementTxHash: string | null;
    createdAt: string;
    updatedAt: string;
  }>;
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

type ManagementStatePayload = {
  ok: boolean;
  agent: {
    agentId: string;
    publicStatus: string;
    metadata: Record<string, unknown>;
  };
  approvalsQueue: Array<{
    trade_id: string;
    chain_key: string;
    pair: string;
    amount_in: string | null;
    token_in: string;
    token_out: string;
    reason: string | null;
    created_at: string;
  }>;
  latestPolicy: {
    mode: 'mock' | 'real';
    approval_mode: 'per_trade' | 'auto';
    max_trade_usd: string | null;
    max_daily_usd: string | null;
    allowed_tokens: string[];
    created_at: string;
  } | null;
  offdexQueue: Array<{
    settlement_intent_id: string;
    chain_key: string;
    status: string;
    maker_token: string;
    taker_token: string;
    maker_amount: string;
    taker_amount: string;
    expires_at: string;
    created_at: string;
  }>;
  auditLog: Array<{
    audit_id: string;
    action_type: string;
    action_status: string;
    public_redacted_payload: Record<string, unknown>;
    created_at: string;
  }>;
  stepup: {
    active: boolean;
    expiresAt: string | null;
  };
  managementSession: {
    sessionId: string;
    expiresAt: string;
  };
};

type ManagementViewState =
  | { phase: 'loading' }
  | { phase: 'unauthorized' }
  | { phase: 'error'; message: string }
  | { phase: 'ready'; data: ManagementStatePayload };

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
      // fallback
    }
    return { ok: false, message };
  }

  return { ok: true };
}

function getCsrfToken(): string | null {
  if (typeof document === 'undefined') {
    return null;
  }
  const raw = document.cookie
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith('xclaw_csrf='));
  if (!raw) {
    return null;
  }
  return decodeURIComponent(raw.split('=')[1] ?? '');
}

async function managementPost(path: string, payload: Record<string, unknown>) {
  const csrf = getCsrfToken();
  const headers: Record<string, string> = {
    'content-type': 'application/json'
  };
  if (csrf) {
    headers['x-csrf-token'] = csrf;
  }

  const response = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers,
    body: JSON.stringify(payload)
  });

  const json = (await response.json().catch(() => null)) as { message?: string } | null;
  if (!response.ok) {
    throw new Error(json?.message ?? 'Management request failed.');
  }
  return json;
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
  const [management, setManagement] = useState<ManagementViewState>({ phase: 'loading' });
  const [error, setError] = useState<string | null>(null);
  const [managementNotice, setManagementNotice] = useState<string | null>(null);
  const [managementError, setManagementError] = useState<string | null>(null);
  const [stepupCode, setStepupCode] = useState('');
  const [withdrawDestination, setWithdrawDestination] = useState('');
  const [withdrawAmount, setWithdrawAmount] = useState('0.1');

  function renderTxHash(hash: string | null): string {
    if (!hash) {
      return '-';
    }
    return `${hash.slice(0, 10)}...${hash.slice(-8)}`;
  }

  function txExplorerUrl(chainKey: string, hash: string | null): string | null {
    if (!hash) {
      return null;
    }
    if (chainKey === 'base_sepolia') {
      return `https://sepolia.basescan.org/tx/${hash}`;
    }
    return null;
  }

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

      rememberManagedAgent(agentId);
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
      setManagementError(null);

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

      try {
        setManagement({ phase: 'loading' });
        const managementRes = await fetch(`/api/v1/management/agent-state?agentId=${encodeURIComponent(agentId)}`, {
          cache: 'no-store',
          credentials: 'same-origin'
        });

        if (managementRes.status === 401) {
          if (!cancelled) {
            setManagement({ phase: 'unauthorized' });
          }
          return;
        }

        if (!managementRes.ok) {
          const payload = (await managementRes.json().catch(() => null)) as { message?: string } | null;
          throw new Error(payload?.message ?? 'Failed to load management state.');
        }

        const payload = (await managementRes.json()) as ManagementStatePayload;
        if (!cancelled) {
          setManagement({ phase: 'ready', data: payload });
          rememberManagedAgent(agentId);

          const savedDestination =
            (payload.agent?.metadata as { management?: { withdrawDestinations?: Record<string, string> } } | undefined)?.management
              ?.withdrawDestinations?.base_sepolia ?? '';
          if (savedDestination) {
            setWithdrawDestination(savedDestination);
          }
        }
      } catch (loadError) {
        if (!cancelled) {
          setManagement({
            phase: 'error',
            message: loadError instanceof Error ? loadError.message : 'Failed to load management state.'
          });
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

  const stepupRemaining = useMemo(() => {
    if (management.phase !== 'ready' || !management.data.stepup.expiresAt || !management.data.stepup.active) {
      return null;
    }

    const ms = new Date(management.data.stepup.expiresAt).getTime() - Date.now();
    if (ms <= 0) {
      return 'expired';
    }

    const hours = Math.floor(ms / (1000 * 60 * 60));
    const minutes = Math.floor((ms % (1000 * 60 * 60)) / (1000 * 60));
    return `${hours}h ${minutes}m`;
  }, [management]);

  async function refreshManagementState() {
    if (!agentId) {
      return;
    }

    try {
      const managementRes = await fetch(`/api/v1/management/agent-state?agentId=${encodeURIComponent(agentId)}`, {
        cache: 'no-store',
        credentials: 'same-origin'
      });

      if (managementRes.status === 401) {
        setManagement({ phase: 'unauthorized' });
        return;
      }

      if (!managementRes.ok) {
        const payload = (await managementRes.json().catch(() => null)) as { message?: string } | null;
        throw new Error(payload?.message ?? 'Failed to refresh management state.');
      }

      const payload = (await managementRes.json()) as ManagementStatePayload;
      setManagement({ phase: 'ready', data: payload });
    } catch (loadError) {
      setManagementError(loadError instanceof Error ? loadError.message : 'Failed to refresh management state.');
    }
  }

  async function runManagementAction(action: () => Promise<void>, successMessage: string) {
    setManagementError(null);
    setManagementNotice(null);
    try {
      await action();
      setManagementNotice(successMessage);
      await refreshManagementState();
    } catch (actionError) {
      setManagementError(actionError instanceof Error ? actionError.message : 'Management action failed.');
    }
  }

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
    <div className="agent-layout">
      <div className="profile-grid">
        {error ? <p className="warning-banner">{error}</p> : null}

        <section className="panel" id="overview">
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

        <section className="panel" id="trades">
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

        <section className="panel" id="offdex">
          <h2 className="section-title">Off-DEX Settlement History</h2>
          {!profile ? <p className="muted">Loading off-DEX history...</p> : null}
          {profile && profile.offdexHistory.length === 0 ? <p className="muted">No off-DEX settlement history yet.</p> : null}
          {profile && profile.offdexHistory.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Role</th>
                    <th>Pair</th>
                    <th>Status</th>
                    <th>Maker Fund Tx</th>
                    <th>Taker Fund Tx</th>
                    <th>Settlement Tx</th>
                    <th>Updated (UTC)</th>
                  </tr>
                </thead>
                <tbody>
                  {profile.offdexHistory.map((intent) => (
                    <tr key={intent.settlementIntentId}>
                      <td>{intent.role}</td>
                      <td>{intent.pairLabel}</td>
                      <td>{intent.status}</td>
                      <td>
                        {txExplorerUrl(intent.chainKey, intent.makerFundTxHash) ? (
                          <a href={txExplorerUrl(intent.chainKey, intent.makerFundTxHash) ?? '#'} target="_blank" rel="noreferrer">
                            {renderTxHash(intent.makerFundTxHash)}
                          </a>
                        ) : (
                          renderTxHash(intent.makerFundTxHash)
                        )}
                      </td>
                      <td>
                        {txExplorerUrl(intent.chainKey, intent.takerFundTxHash) ? (
                          <a href={txExplorerUrl(intent.chainKey, intent.takerFundTxHash) ?? '#'} target="_blank" rel="noreferrer">
                            {renderTxHash(intent.takerFundTxHash)}
                          </a>
                        ) : (
                          renderTxHash(intent.takerFundTxHash)
                        )}
                      </td>
                      <td>
                        {txExplorerUrl(intent.chainKey, intent.settlementTxHash) ? (
                          <a href={txExplorerUrl(intent.chainKey, intent.settlementTxHash) ?? '#'} target="_blank" rel="noreferrer">
                            {renderTxHash(intent.settlementTxHash)}
                          </a>
                        ) : (
                          renderTxHash(intent.settlementTxHash)
                        )}
                      </td>
                      <td>{formatUtc(intent.updatedAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </section>

        <section className="panel" id="activity">
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

      <aside className="management-rail" id="management">
        <section className="panel">
          <h2 className="section-title">Management</h2>

          {managementNotice ? <p className="success-banner">{managementNotice}</p> : null}
          {managementError ? <p className="warning-banner">{managementError}</p> : null}

          {management.phase === 'loading' ? <p className="muted">Loading management state...</p> : null}
          {management.phase === 'unauthorized' ? (
            <p className="muted">Unauthorized: management controls require bootstrap token session.</p>
          ) : null}
          {management.phase === 'error' ? <p className="warning-banner">{management.message}</p> : null}

          {management.phase === 'ready' ? (
            <div className="management-stack">
              <article className="management-card">
                <h3>Step-up Status</h3>
                <p>
                  {management.data.stepup.active ? 'Active' : 'Inactive'}
                  {stepupRemaining ? ` (${stepupRemaining} remaining)` : ''}
                </p>
                <div className="toolbar">
                  <button
                    className="theme-toggle"
                    type="button"
                    onClick={() =>
                      void runManagementAction(
                        () => managementPost('/api/v1/management/stepup/challenge', { agentId, issuedFor: 'withdraw' }).then(() => Promise.resolve()),
                        'Step-up challenge issued. Check code response in API logs for this MVP path.'
                      )
                    }
                  >
                    Request Step-up Code
                  </button>
                </div>
                <div className="toolbar">
                  <input value={stepupCode} onChange={(event) => setStepupCode(event.target.value)} placeholder="Step-up code" />
                  <button
                    className="theme-toggle"
                    type="button"
                    onClick={() =>
                      void runManagementAction(
                        () => managementPost('/api/v1/management/stepup/verify', { agentId, code: stepupCode }).then(() => Promise.resolve()),
                        'Step-up verified.'
                      )
                    }
                  >
                    Verify
                  </button>
                </div>
              </article>

              <article className="management-card">
                <h3>Approval Queue</h3>
                {management.data.approvalsQueue.length === 0 ? <p className="muted">No pending approvals.</p> : null}
                {management.data.approvalsQueue.map((item) => (
                  <div key={item.trade_id} className="queue-item">
                    <div>
                      <strong>{item.pair}</strong>
                      <div className="muted">{formatUtc(item.created_at)} UTC</div>
                    </div>
                    <div className="toolbar">
                      <button
                        type="button"
                        className="theme-toggle"
                        onClick={() =>
                          void runManagementAction(
                            () => managementPost('/api/v1/management/approvals/decision', { agentId, tradeId: item.trade_id, decision: 'approve' }).then(() => Promise.resolve()),
                            `Approved ${item.trade_id}`
                          )
                        }
                      >
                        Approve
                      </button>
                      <button
                        type="button"
                        className="theme-toggle"
                        onClick={() =>
                          void runManagementAction(
                            () =>
                              managementPost('/api/v1/management/approvals/decision', {
                                agentId,
                                tradeId: item.trade_id,
                                decision: 'reject',
                                reasonCode: 'approval_rejected'
                              }).then(() => Promise.resolve()),
                            `Rejected ${item.trade_id}`
                          )
                        }
                      >
                        Reject
                      </button>
                    </div>
                  </div>
                ))}
              </article>

              <article className="management-card">
                <h3>Policy Controls</h3>
                <div className="toolbar">
                  <button
                    type="button"
                    className="theme-toggle"
                    onClick={() =>
                      void runManagementAction(
                        () =>
                          managementPost('/api/v1/management/policy/update', {
                            agentId,
                            mode: management.data.latestPolicy?.mode ?? 'mock',
                            approvalMode: management.data.latestPolicy?.approval_mode ?? 'per_trade',
                            maxTradeUsd: management.data.latestPolicy?.max_trade_usd ?? '50',
                            maxDailyUsd: management.data.latestPolicy?.max_daily_usd ?? '250',
                            allowedTokens: management.data.latestPolicy?.allowed_tokens ?? []
                          }).then(() => Promise.resolve()),
                        'Policy updated.'
                      )
                    }
                  >
                    Save Current Policy
                  </button>
                </div>
                <div className="toolbar">
                  <button
                    type="button"
                    className="theme-toggle"
                    onClick={() =>
                      void runManagementAction(
                        () => managementPost('/api/v1/management/pause', { agentId }).then(() => Promise.resolve()),
                        'Agent paused.'
                      )
                    }
                  >
                    Pause
                  </button>
                  <button
                    type="button"
                    className="theme-toggle"
                    onClick={() =>
                      void runManagementAction(
                        () => managementPost('/api/v1/management/resume', { agentId }).then(() => Promise.resolve()),
                        'Agent resumed.'
                      )
                    }
                  >
                    Resume
                  </button>
                </div>
                <div className="toolbar">
                  <button
                    type="button"
                    className="theme-toggle"
                    onClick={() =>
                      void runManagementAction(
                        () =>
                          managementPost('/api/v1/management/approvals/scope', {
                            agentId,
                            chainKey: 'base_sepolia',
                            scope: 'global',
                            action: 'grant',
                            maxAmountUsd: '50',
                            slippageBpsMax: 50,
                            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
                          }).then(() => Promise.resolve()),
                        'Global approval scope updated.'
                      )
                    }
                  >
                    Grant Global Approval
                  </button>
                </div>
              </article>

              <article className="management-card">
                <h3>Withdraw Controls</h3>
                <div className="toolbar">
                  <input
                    value={withdrawDestination}
                    onChange={(event) => setWithdrawDestination(event.target.value)}
                    placeholder="Destination 0x..."
                  />
                  <button
                    type="button"
                    className="theme-toggle"
                    onClick={() =>
                      void runManagementAction(
                        () =>
                          managementPost('/api/v1/management/withdraw/destination', {
                            agentId,
                            chainKey: 'base_sepolia',
                            destination: withdrawDestination
                          }).then(() => Promise.resolve()),
                        'Withdraw destination saved.'
                      )
                    }
                  >
                    Save Destination
                  </button>
                </div>
                <div className="toolbar">
                  <input value={withdrawAmount} onChange={(event) => setWithdrawAmount(event.target.value)} placeholder="Amount" />
                  <button
                    type="button"
                    className="theme-toggle"
                    onClick={() =>
                      void runManagementAction(
                        () =>
                          managementPost('/api/v1/management/withdraw', {
                            agentId,
                            chainKey: 'base_sepolia',
                            asset: 'ETH',
                            amount: withdrawAmount,
                            destination: withdrawDestination
                          }).then(() => Promise.resolve()),
                        'Withdraw request submitted.'
                      )
                    }
                  >
                    Request Withdraw
                  </button>
                </div>
              </article>

              <article className="management-card">
                <h3>Off-DEX Settlement Queue</h3>
                {management.data.offdexQueue.length === 0 ? <p className="muted">No pending off-DEX intents.</p> : null}
                {management.data.offdexQueue.map((intent) => (
                  <div key={intent.settlement_intent_id} className="queue-item">
                    <div>
                      <strong>
                        {intent.maker_token}/{intent.taker_token}
                      </strong>
                      <div className="muted">{intent.status}</div>
                    </div>
                    <div className="toolbar">
                      <button
                        type="button"
                        className="theme-toggle"
                        onClick={() =>
                          void runManagementAction(
                            () =>
                              managementPost('/api/v1/management/offdex/decision', {
                                agentId,
                                intentId: intent.settlement_intent_id,
                                action: 'approve'
                              }).then(() => Promise.resolve()),
                            `Off-DEX intent approved: ${intent.settlement_intent_id}`
                          )
                        }
                      >
                        Approve
                      </button>
                      <button
                        type="button"
                        className="theme-toggle"
                        onClick={() =>
                          void runManagementAction(
                            () =>
                              managementPost('/api/v1/management/offdex/decision', {
                                agentId,
                                intentId: intent.settlement_intent_id,
                                action: 'settle_request'
                              }).then(() => Promise.resolve()),
                            `Settlement requested: ${intent.settlement_intent_id}`
                          )
                        }
                      >
                        Settle Request
                      </button>
                      <button
                        type="button"
                        className="theme-toggle"
                        onClick={() =>
                          void runManagementAction(
                            () =>
                              managementPost('/api/v1/management/offdex/decision', {
                                agentId,
                                intentId: intent.settlement_intent_id,
                                action: 'cancel'
                              }).then(() => Promise.resolve()),
                            `Off-DEX intent cancelled: ${intent.settlement_intent_id}`
                          )
                        }
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ))}
              </article>

              <article className="management-card">
                <h3>Management Audit Log</h3>
                {management.data.auditLog.length === 0 ? <p className="muted">No audit entries.</p> : null}
                <div className="audit-list">
                  {management.data.auditLog.map((entry) => (
                    <div className="audit-item" key={entry.audit_id}>
                      <div>
                        <strong>{entry.action_type}</strong> ({entry.action_status})
                      </div>
                      <div className="muted">{formatUtc(entry.created_at)} UTC</div>
                    </div>
                  ))}
                </div>
              </article>
            </div>
          ) : null}
        </section>
      </aside>
    </div>
  );
}
