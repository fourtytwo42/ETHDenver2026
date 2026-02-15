'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { useParams, useRouter, useSearchParams } from 'next/navigation';

import { rememberManagedAgent } from '@/components/management-header-controls';
import { PublicStatusBadge } from '@/components/public-status-badge';
import { useActiveChainKey } from '@/lib/active-chain';
import { formatNumber, formatPercent, formatUsd, formatUtc, isStale, shortenAddress } from '@/lib/public-format';
import { isPublicStatus } from '@/lib/public-types';

type BootstrapState =
  | { phase: 'bootstrapping' }
  | { phase: 'error'; message: string; code?: string; actionHint?: string }
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
    last_heartbeat_at: string | null;
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
  copyBreakdown:
    | {
        selfTradesCount: number;
        copiedTradesCount: number;
        selfVolumeUsd: string | null;
        copiedVolumeUsd: string | null;
        selfPnlUsd: string | null;
        copiedPnlUsd: string | null;
      }
    | null;
};

type TradePayload = {
  ok: boolean;
  items: Array<{
    trade_id: string;
    source_trade_id: string | null;
    source_label?: 'self' | 'copied';
    chain_key: string;
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
    chain_key: string;
    pair_display: string | null;
    token_in_symbol: string | null;
    token_out_symbol: string | null;
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
  chainPolicy: {
    chainKey: string;
    chainEnabled: boolean;
    updatedAt: string | null;
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
    mode: 'real';
    approval_mode: 'per_trade' | 'auto';
    max_trade_usd: string | null;
    max_daily_usd: string | null;
    max_daily_trade_count: string | null;
    daily_cap_usd_enabled: boolean;
    daily_trade_cap_enabled: boolean;
    allowed_tokens: string[];
    created_at: string;
  } | null;
  tradeCaps: {
    dailyCapUsdEnabled: boolean;
    dailyTradeCapEnabled: boolean;
    maxDailyTradeCount: number | null;
  };
  dailyUsage: {
    utcDay: string;
    dailySpendUsd: string;
    dailyFilledTrades: number;
  };
  outboundTransfersPolicy: {
    outboundTransfersEnabled: boolean;
    outboundMode: 'disabled' | 'allow_all' | 'whitelist';
    outboundWhitelistAddresses: string[];
    updatedAt: string | null;
  };
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

type DepositPayload = {
  ok: boolean;
  agentId: string;
  chains: Array<{
    chainKey: string;
    depositAddress: string;
    minConfirmations: number;
    lastSyncedAt: string | null;
    syncStatus: 'ok' | 'degraded';
    syncDetail: string | null;
    balances: Array<{
      token: string;
      balance: string;
      blockNumber: number | null;
      observedAt: string;
    }>;
    recentDeposits: Array<{
      token: string;
      amount: string;
      txHash: string;
      blockNumber: number;
      confirmedAt: string;
      status: string;
    }>;
    explorerBaseUrl: string | null;
  }>;
};

type LimitOrderItem = {
  orderId: string;
  agentId: string;
  chainKey: string;
  mode: 'real';
  side: 'buy' | 'sell';
  tokenIn: string;
  tokenOut: string;
  amountIn: string;
  limitPrice: string;
  slippageBps: number;
  status: string;
  expiresAt: string | null;
  cancelledAt: string | null;
  triggerSource: string;
  createdAt: string;
  updatedAt: string;
};

const HEARTBEAT_STALE_THRESHOLD_SECONDS = 180;

function formatActivityTitle(eventType: string): string {
  if (eventType === 'trade_filled') {
    return 'Trade filled';
  }
  if (eventType === 'trade_failed') {
    return 'Trade failed';
  }
  if (eventType === 'trade_executing') {
    return 'Trade executing';
  }
  if (eventType === 'trade_approval_pending') {
    return 'Awaiting approval';
  }
  if (eventType.startsWith('trade_')) {
    return eventType.replace(/^trade_/, '').replace(/_/g, ' ');
  }
  return eventType.replace(/_/g, ' ');
}

function usagePercent(current: number, maxRaw: string, enabled: boolean): number {
  if (!enabled) {
    return 0;
  }
  const max = Number(maxRaw);
  if (!Number.isFinite(max) || max <= 0) {
    return 0;
  }
  return Math.max(0, Math.min(100, (current / max) * 100));
}

function CopyIcon() {
  return (
    <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <rect x="4" y="4" width="11" height="11" rx="2" />
    </svg>
  );
}

async function bootstrapSession(
  agentId: string,
  token: string
): Promise<{ ok: true } | { ok: false; message: string; code?: string; actionHint?: string }> {
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
    let code: string | undefined;
    let actionHint: string | undefined;
    try {
      const payload = (await response.json()) as { message?: string; code?: string; actionHint?: string };
      if (payload?.message) {
        message = payload.message;
      }
      if (typeof payload?.code === 'string' && payload.code.trim()) {
        code = payload.code.trim();
      }
      if (typeof payload?.actionHint === 'string' && payload.actionHint.trim()) {
        actionHint = payload.actionHint.trim();
      }
    } catch {
      // fallback
    }
    return { ok: false, message, code, actionHint };
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

  const json = (await response.json().catch(() => null)) as { message?: string; code?: string; actionHint?: string } | null;
  if (!response.ok) {
    const error = new Error(json?.message ?? 'Management request failed.') as Error & { code?: string; actionHint?: string };
    if (json?.code) {
      error.code = json.code;
    }
    if (json?.actionHint) {
      error.actionHint = json.actionHint;
    }
    throw error;
  }
  return json;
}

async function managementGet(path: string) {
  const csrf = getCsrfToken();
  const headers: Record<string, string> = {};
  if (csrf) {
    headers['x-csrf-token'] = csrf;
  }

  const response = await fetch(path, {
    method: 'GET',
    credentials: 'same-origin',
    headers,
    cache: 'no-store'
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
  const [activeChainKey, , activeChainLabel] = useActiveChainKey();

  const [bootstrapState, setBootstrapState] = useState<BootstrapState>({ phase: 'ready' });
  const [profile, setProfile] = useState<AgentProfilePayload | null>(null);
  const [trades, setTrades] = useState<TradePayload['items'] | null>(null);
  const [activity, setActivity] = useState<ActivityPayload['items'] | null>(null);
  const [management, setManagement] = useState<ManagementViewState>({ phase: 'loading' });
  const [error, setError] = useState<string | null>(null);
  const [managementNotice, setManagementNotice] = useState<string | null>(null);
  const [managementError, setManagementError] = useState<string | null>(null);
  const [stepupPromptOpen, setStepupPromptOpen] = useState(false);
  const [stepupPromptCode, setStepupPromptCode] = useState('');
  const [stepupPromptIssuedFor, setStepupPromptIssuedFor] = useState<'withdraw' | 'approval_scope_change' | 'sensitive_action'>(
    'sensitive_action'
  );
  const [withdrawDestination, setWithdrawDestination] = useState('');
  const [withdrawAmount, setWithdrawAmount] = useState('0.1');
  const [depositCopied, setDepositCopied] = useState(false);
  const [overviewDepositCopied, setOverviewDepositCopied] = useState(false);
  const [depositData, setDepositData] = useState<DepositPayload | null>(null);
  const [limitOrders, setLimitOrders] = useState<LimitOrderItem[]>([]);
  const pendingStepupActionRef = useRef<{
    action: () => Promise<void>;
    successMessage: string;
    issuedFor: 'withdraw' | 'approval_scope_change' | 'sensitive_action';
  } | null>(null);
  const [outboundTransfersEnabled, setOutboundTransfersEnabled] = useState(false);
  const [outboundMode, setOutboundMode] = useState<'disabled' | 'allow_all' | 'whitelist'>('disabled');
  const [outboundWhitelistInput, setOutboundWhitelistInput] = useState('');
  const [policyApprovalMode, setPolicyApprovalMode] = useState<'per_trade' | 'auto'>('per_trade');
  const [policyMaxTradeUsd, setPolicyMaxTradeUsd] = useState('50');
  const [policyMaxDailyUsd, setPolicyMaxDailyUsd] = useState('250');
  const [policyDailyCapUsdEnabled, setPolicyDailyCapUsdEnabled] = useState(true);
  const [policyDailyTradeCapEnabled, setPolicyDailyTradeCapEnabled] = useState(true);
  const [policyMaxDailyTradeCount, setPolicyMaxDailyTradeCount] = useState('0');
  const [policyAllowedTokensInput, setPolicyAllowedTokensInput] = useState('');
  const [chainUpdatePending, setChainUpdatePending] = useState(false);

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
        setBootstrapState({
          phase: 'error',
          message: result.message,
          code: result.code,
          actionHint: result.actionHint
        });
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
          fetch(`/api/v1/public/activity?limit=20&agentId=${encodeURIComponent(agentId)}`, { cache: 'no-store' })
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
          setActivity(activityPayload.items.slice(0, 12));
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError instanceof Error ? loadError.message : 'Failed to load public profile data.');
        }
      }

      try {
        setManagement({ phase: 'loading' });
        const managementRes = await fetch(
          `/api/v1/management/agent-state?agentId=${encodeURIComponent(agentId)}&chainKey=${encodeURIComponent(activeChainKey)}`,
          {
          cache: 'no-store',
          credentials: 'same-origin'
          }
        );

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
          setOutboundTransfersEnabled(payload.outboundTransfersPolicy.outboundTransfersEnabled);
          setOutboundMode(payload.outboundTransfersPolicy.outboundMode);
          setOutboundWhitelistInput(payload.outboundTransfersPolicy.outboundWhitelistAddresses.join(','));
          setPolicyApprovalMode(payload.latestPolicy?.approval_mode ?? 'per_trade');
          setPolicyMaxTradeUsd(payload.latestPolicy?.max_trade_usd ?? '50');
          setPolicyMaxDailyUsd(payload.latestPolicy?.max_daily_usd ?? '250');
          setPolicyDailyCapUsdEnabled(payload.tradeCaps?.dailyCapUsdEnabled ?? payload.latestPolicy?.daily_cap_usd_enabled ?? true);
          setPolicyDailyTradeCapEnabled(payload.tradeCaps?.dailyTradeCapEnabled ?? payload.latestPolicy?.daily_trade_cap_enabled ?? true);
          setPolicyMaxDailyTradeCount(
            payload.tradeCaps?.maxDailyTradeCount !== null && payload.tradeCaps?.maxDailyTradeCount !== undefined
              ? String(payload.tradeCaps.maxDailyTradeCount)
              : (payload.latestPolicy?.max_daily_trade_count ?? '0')
          );
          setPolicyAllowedTokensInput((payload.latestPolicy?.allowed_tokens ?? []).join(','));
          rememberManagedAgent(agentId);

          const savedDestination =
            (payload.agent?.metadata as { management?: { withdrawDestinations?: Record<string, string> } } | undefined)?.management
              ?.withdrawDestinations?.[activeChainKey] ??
            (payload.agent?.metadata as { management?: { withdrawDestinations?: Record<string, string> } } | undefined)?.management
              ?.withdrawDestinations?.base_sepolia ??
            '';
          if (savedDestination) {
            setWithdrawDestination(savedDestination);
          }

          const [depositPayload, limitOrderPayload] = await Promise.all([
            managementGet(
              `/api/v1/management/deposit?agentId=${encodeURIComponent(agentId)}&chainKey=${encodeURIComponent(activeChainKey)}`
            ),
            managementGet(`/api/v1/management/limit-orders?agentId=${encodeURIComponent(agentId)}&limit=50`)
          ]);
          setDepositData(depositPayload as DepositPayload);
          setLimitOrders(((limitOrderPayload as { items?: LimitOrderItem[] }).items ?? []).filter(Boolean));
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
  }, [agentId, bootstrapState.phase, activeChainKey]);

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
      const managementRes = await fetch(
        `/api/v1/management/agent-state?agentId=${encodeURIComponent(agentId)}&chainKey=${encodeURIComponent(activeChainKey)}`,
        {
          cache: 'no-store',
          credentials: 'same-origin'
        }
      );

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
      setOutboundTransfersEnabled(payload.outboundTransfersPolicy.outboundTransfersEnabled);
      setOutboundMode(payload.outboundTransfersPolicy.outboundMode);
      setOutboundWhitelistInput(payload.outboundTransfersPolicy.outboundWhitelistAddresses.join(','));
      setPolicyApprovalMode(payload.latestPolicy?.approval_mode ?? 'per_trade');
      setPolicyMaxTradeUsd(payload.latestPolicy?.max_trade_usd ?? '50');
      setPolicyMaxDailyUsd(payload.latestPolicy?.max_daily_usd ?? '250');
      setPolicyDailyCapUsdEnabled(payload.tradeCaps?.dailyCapUsdEnabled ?? payload.latestPolicy?.daily_cap_usd_enabled ?? true);
      setPolicyDailyTradeCapEnabled(payload.tradeCaps?.dailyTradeCapEnabled ?? payload.latestPolicy?.daily_trade_cap_enabled ?? true);
      setPolicyMaxDailyTradeCount(
        payload.tradeCaps?.maxDailyTradeCount !== null && payload.tradeCaps?.maxDailyTradeCount !== undefined
          ? String(payload.tradeCaps.maxDailyTradeCount)
          : (payload.latestPolicy?.max_daily_trade_count ?? '0')
      );
      setPolicyAllowedTokensInput((payload.latestPolicy?.allowed_tokens ?? []).join(','));
      const [depositPayload, limitOrderPayload] = await Promise.all([
        managementGet(`/api/v1/management/deposit?agentId=${encodeURIComponent(agentId)}&chainKey=${encodeURIComponent(activeChainKey)}`),
        managementGet(`/api/v1/management/limit-orders?agentId=${encodeURIComponent(agentId)}&limit=50`)
      ]);
      setDepositData(depositPayload as DepositPayload);
      setLimitOrders(((limitOrderPayload as { items?: LimitOrderItem[] }).items ?? []).filter(Boolean));
    } catch (loadError) {
      setManagementError(loadError instanceof Error ? loadError.message : 'Failed to refresh management state.');
    }
  }

  async function runManagementAction(
    action: () => Promise<void>,
    successMessage: string,
    issuedFor: 'withdraw' | 'approval_scope_change' | 'sensitive_action' = 'sensitive_action'
  ) {
    setManagementError(null);
    setManagementNotice(null);
    try {
      await action();
      setManagementNotice(successMessage);
      await refreshManagementState();
      pendingStepupActionRef.current = null;
      setStepupPromptOpen(false);
      setStepupPromptCode('');
    } catch (actionError) {
      const coded = actionError as Error & { code?: string; actionHint?: string };
      if (coded?.code === 'stepup_required' || coded?.code === 'stepup_expired' || coded?.code === 'stepup_invalid') {
        pendingStepupActionRef.current = { action, successMessage, issuedFor };
        setStepupPromptIssuedFor(issuedFor);
        setStepupPromptOpen(true);
        setManagementError('Step-up required. Ask your agent for a step-up code using `stepup-code`, then enter it below.');
        return;
      }
      setManagementError(actionError instanceof Error ? actionError.message : 'Management action failed.');
      try {
        await refreshManagementState();
      } catch {
        // ignore refresh failures on error path
      }
    }
  }

  async function submitStepupPrompt() {
    if (!agentId) {
      return;
    }
    const queued = pendingStepupActionRef.current;
    if (!queued) {
      setManagementError('No pending protected action to retry.');
      return;
    }
    if (!stepupPromptCode.trim()) {
      setManagementError('Enter a step-up code from your agent to continue.');
      return;
    }

    setManagementError(null);
    setManagementNotice(null);
    try {
      await managementPost('/api/v1/management/stepup/verify', { agentId, code: stepupPromptCode.trim() });
      setStepupPromptCode('');
      setStepupPromptOpen(false);
      await runManagementAction(queued.action, queued.successMessage, queued.issuedFor);
    } catch (error) {
      setManagementError(error instanceof Error ? error.message : 'Step-up verification failed.');
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
        {bootstrapState.code ? <p className="muted">Code: {bootstrapState.code}</p> : null}
        {bootstrapState.actionHint ? <p className="muted">{bootstrapState.actionHint}</p> : null}
      </main>
    );
  }

  return (
    <div className="agent-layout">
      <div className="profile-grid">
        {error ? <p className="warning-banner">{error}</p> : null}

        <section className="panel" id="overview">
          <h1 className="section-title">Agent Overview</h1>
          {!profile ? <p className="muted">Loading agent profile...</p> : null}

          {profile ? (
            <>
              <div className="identity-row">
                <strong>{profile.agent.agent_name}</strong>
                {isPublicStatus(profile.agent.public_status) ? <PublicStatusBadge status={profile.agent.public_status} /> : profile.agent.public_status}
                <span className="muted">{profile.agent.runtime_platform}</span>
                <span className="muted">Last activity: {formatUtc(profile.agent.last_activity_at)} UTC</span>
              </div>
              {isStale(profile.agent.last_heartbeat_at, HEARTBEAT_STALE_THRESHOLD_SECONDS) ? (
                <p className="stale">Agent is idle.</p>
              ) : (
                <p className="muted">Idle (heartbeat healthy).</p>
              )}
              {profile.agent.description ? <p style={{ marginTop: '0.8rem' }}>{profile.agent.description}</p> : null}

              <div style={{ marginTop: '0.8rem' }}>
                <div className="muted">Deposit address</div>
                {(() => {
                  const activeWallet = (profile.wallets ?? []).find((w) => w.chain_key === activeChainKey) ?? null;
                  const address = activeWallet?.address ?? null;
                  return (
                    <button
                      type="button"
                      className="copy-row"
                      disabled={!address}
                      onClick={async () => {
                        if (!address) return;
                        try {
                          await navigator.clipboard.writeText(address);
                          setOverviewDepositCopied(true);
                          window.setTimeout(() => setOverviewDepositCopied(false), 1000);
                        } catch {
                          setOverviewDepositCopied(false);
                        }
                      }}
                      aria-label={address ? 'Copy deposit address' : 'Deposit address unavailable'}
                      title={address ? 'Copy deposit address' : 'Deposit address unavailable'}
                    >
                    <span className="copy-row-icon">
                      <CopyIcon />
                    </span>
                    <span className="copy-row-text">{address ? shortenAddress(address) : '-'}</span>
                  </button>
                );
              })()}
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
          <p className="muted">Recent network trades for this agent. Timestamps are UTC.</p>
          {!trades ? <p className="muted">Loading trades...</p> : null}
          {trades && trades.length === 0 ? <p className="muted">No trades found for this agent.</p> : null}
          {trades && trades.length > 0 ? (
            <>
              <div className="table-desktop">
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Source</th>
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
                          <td>{trade.source_label ?? (trade.source_trade_id ? 'copied' : 'self')}</td>
                          <td>{trade.pair}</td>
                          <td>
                            <span className="status-chip">{trade.status}</span>
                          </td>
                          <td className="hard-wrap">{trade.tx_hash ?? '-'}</td>
                          <td>{trade.reason_code ?? trade.reason_message ?? trade.reason ?? '-'}</td>
                          <td>{formatUtc(trade.created_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
              <div className="cards-mobile">
                <div className="cards-mobile-grid">
                  {trades.map((trade) => (
                    <article key={`${trade.trade_id}:mobile`} className="data-card">
                      <div>
                        <strong>{trade.pair}</strong>
                      </div>
                      <div className="toolbar" style={{ marginBottom: 0 }}>
                        <span className="status-chip">{trade.status}</span>
                      </div>
                      <div className="data-pairs">
                        <div>
                          <div className="data-label">Source</div>
                          <div className="data-value">{trade.source_label ?? (trade.source_trade_id ? 'copied' : 'self')}</div>
                        </div>
                        <div>
                          <div className="data-label">Execution ID</div>
                          <div className="data-value hard-wrap">{trade.tx_hash ?? '-'}</div>
                        </div>
                        <div>
                          <div className="data-label">Reason</div>
                          <div className="data-value">{trade.reason_code ?? trade.reason_message ?? trade.reason ?? '-'}</div>
                        </div>
                        <div>
                          <div className="data-label">Created (UTC)</div>
                          <div className="data-value">{formatUtc(trade.created_at)}</div>
                        </div>
                      </div>
                    </article>
                  ))}
                </div>
              </div>
            </>
          ) : null}
          {profile?.copyBreakdown ? (
            <div style={{ marginTop: '0.8rem' }}>
              <div className="muted">Copy Breakdown (7d)</div>
              <div>
                Self trades: {formatNumber(profile.copyBreakdown.selfTradesCount)} | Copied trades:{' '}
                {formatNumber(profile.copyBreakdown.copiedTradesCount)}
              </div>
              <div>
                Self PnL: {formatUsd(profile.copyBreakdown.selfPnlUsd)} | Copied PnL: {formatUsd(profile.copyBreakdown.copiedPnlUsd)}
              </div>
            </div>
          ) : null}
        </section>

        <section className="panel" id="activity">
          <h2 className="section-title">Activity Timeline</h2>
          <p className="muted">Live trade-related events for this agent.</p>
          {!activity ? <p className="muted">Loading activity...</p> : null}
          {activity && activity.length === 0 ? <p className="muted">No activity yet on Base Sepolia.</p> : null}
          {activity && activity.length > 0 ? (
            <div className="activity-list">
              {activity.map((event) => (
                <article className="activity-item" key={event.event_id}>
                  <div>
                    <strong>{formatActivityTitle(event.event_type)}</strong>
                    <div className="muted">
                      {event.pair_display ?? `${event.token_in_symbol ?? 'token'} -> ${event.token_out_symbol ?? 'token'}`}
                    </div>
                  </div>
                  <div className="muted">
                    {event.chain_key} • {formatUtc(event.created_at)} UTC
                  </div>
                </article>
              ))}
            </div>
          ) : null}
        </section>
      </div>

      <aside className="management-rail" id="management">
        <section className="panel">
          <h2 className="section-title">Management</h2>
          <p className="muted">
            Session:{' '}
            {management.phase === 'ready'
              ? 'Management session active for this host.'
              : management.phase === 'unauthorized'
                ? 'No active management session for this host.'
                : 'Checking management session...'}
          </p>

          {managementNotice ? <p className="success-banner">{managementNotice}</p> : null}
          {managementError ? <p className="warning-banner">{managementError}</p> : null}

          {management.phase === 'loading' ? <p className="muted">Loading management state...</p> : null}
          {management.phase === 'unauthorized' ? (
            <div className="muted">
              <p>Unauthorized: management controls require a bootstrap token session on this host.</p>
              <p>Owner links are one-time use. If one was already used elsewhere, ask the agent to generate a fresh link.</p>
              <p>Open the fresh link directly on https://xclaw.trade.</p>
            </div>
          ) : null}
          {management.phase === 'error' ? <p className="warning-banner">{management.message}</p> : null}

          {management.phase === 'ready' ? (
            <div className="management-stack">
              <article className="management-card">
                <h3>Session and Step-up</h3>
                <p className="muted">Session expires at {formatUtc(management.data.managementSession.expiresAt)} UTC.</p>
                <p>
                  Step-up: <strong>{management.data.stepup.active ? 'Active' : 'Inactive'}</strong>
                  {stepupRemaining ? ` (${stepupRemaining} remaining)` : ''}
                </p>
                <p className="muted">
                  Step-up codes are not generated manually here. If a protected action requires step-up, you will be prompted and must ask the
                  agent for a code (`stepup-code`).
                </p>
                {stepupPromptOpen ? (
                  <div className="queue-item">
                    <div className="muted">Protected action blocked. Ask your agent for a step-up code, then verify to continue.</div>
                    <div className="toolbar">
                      <input
                        value={stepupPromptCode}
                        onChange={(event) => setStepupPromptCode(event.target.value)}
                        placeholder={`Step-up code (${stepupPromptIssuedFor})`}
                      />
                      <button className="theme-toggle" type="button" onClick={() => void submitStepupPrompt()}>
                        Verify and Continue
                      </button>
                    </div>
                  </div>
                ) : null}
              </article>

              <article className="management-card">
                <h3>Safety Controls</h3>
                <p className="muted">Control runtime safety and outbound transfer restrictions.</p>
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
                    Pause Agent
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
                    Resume Agent
                  </button>
                </div>
                <div className="toolbar">
                  <label>
                    <input
                      type="checkbox"
                      checked={outboundTransfersEnabled}
                      onChange={(event) => setOutboundTransfersEnabled(event.target.checked)}
                    />{' '}
                    Outbound transfers enabled
                  </label>
                  <select
                    value={outboundMode}
                    onChange={(event) => setOutboundMode((event.target.value as 'disabled' | 'allow_all' | 'whitelist') ?? 'disabled')}
                  >
                    <option value="disabled">disabled</option>
                    <option value="allow_all">allow_all</option>
                    <option value="whitelist">whitelist</option>
                  </select>
                </div>
                <div className="toolbar">
                  <input
                    value={outboundWhitelistInput}
                    onChange={(event) => setOutboundWhitelistInput(event.target.value)}
                    placeholder="Comma-separated whitelist addresses"
                  />
                </div>
                <div className="toolbar">
                  <button
                    className="theme-toggle"
                    type="button"
                    onClick={() =>
                      void runManagementAction(
                        () =>
                          managementPost('/api/v1/management/policy/update', {
                            agentId,
                            mode: 'real',
                            approvalMode: policyApprovalMode,
                            maxTradeUsd: policyMaxTradeUsd,
                            maxDailyUsd: policyMaxDailyUsd,
                            dailyCapUsdEnabled: policyDailyCapUsdEnabled,
                            dailyTradeCapEnabled: policyDailyTradeCapEnabled,
                            maxDailyTradeCount: policyDailyTradeCapEnabled ? Number(policyMaxDailyTradeCount || '0') : null,
                            allowedTokens: policyAllowedTokensInput
                              .split(',')
                              .map((value) => value.trim())
                              .filter((value) => value.length > 0),
                            outboundTransfersEnabled,
                            outboundMode,
                            outboundWhitelistAddresses: outboundWhitelistInput
                              .split(',')
                              .map((value) => value.trim())
                              .filter((value) => value.length > 0)
                          }).then(() => Promise.resolve()),
                        'Transfer policy saved.',
                        'sensitive_action'
                      )
                    }
                  >
                    Save Transfer Policy
                  </button>
                </div>
              </article>

              <article className="management-card">
                <h3>Chain Access</h3>
                <p className="muted">Enable or disable agent trading and wallet-send for the active chain.</p>
                <p className="muted">
                  Active chain: <strong>{activeChainLabel}</strong>
                </p>
                <div className="toolbar">
                  <label>
                    <input
                      type="checkbox"
                      checked={management.data.chainPolicy?.chainEnabled ?? true}
                      disabled={chainUpdatePending}
                      onChange={(event) => {
                        const next = Boolean(event.target.checked);
                        setChainUpdatePending(true);
                        void (async () => {
                          await runManagementAction(
                            () =>
                              managementPost('/api/v1/management/chains/update', {
                                agentId,
                                chainKey: activeChainKey,
                                chainEnabled: next
                              }).then(() => Promise.resolve()),
                            next ? 'Chain enabled.' : 'Chain disabled.',
                            'sensitive_action'
                          );
                          setChainUpdatePending(false);
                        })();
                      }}
                    />{' '}
                    Chain enabled
                  </label>
                  <span className="muted">
                    {management.data.chainPolicy?.updatedAt ? `Updated ${formatUtc(management.data.chainPolicy.updatedAt)} UTC` : 'Default: enabled'}
                  </span>
                </div>
                {management.data.chainPolicy?.chainEnabled ? (
                  <p className="muted">Agent trading + wallet send are allowed on this chain.</p>
                ) : (
                  <p className="warning-banner">Disabled: agent cannot trade or wallet-send on this chain.</p>
                )}
              </article>

              <article className="management-card">
                <h3>Deposit and Withdraw</h3>
                <p className="muted">Deposit address and withdrawals for the active chain.</p>
                {depositData?.chains?.[0]?.depositAddress ? (
                  <button
                    type="button"
                    className="copy-row"
                    onClick={async () => {
                      try {
                        await navigator.clipboard.writeText(depositData.chains[0].depositAddress);
                        setDepositCopied(true);
                        window.setTimeout(() => setDepositCopied(false), 1000);
                      } catch {
                        setDepositCopied(false);
                      }
                    }}
                    aria-label="Copy deposit address"
                    title="Copy deposit address"
                  >
                    <span className="copy-row-icon">
                      <CopyIcon />
                    </span>
                    <span className="copy-row-text">
                      {depositData.chains[0].chainKey}: {shortenAddress(depositData.chains[0].depositAddress)}
                    </span>
                  </button>
                ) : (
                  <p className="muted">Loading deposit address...</p>
                )}

                <div className="toolbar" style={{ marginTop: '0.6rem' }}>
                  <input
                    value={withdrawDestination}
                    onChange={(event) => setWithdrawDestination(event.target.value)}
                    placeholder="Withdraw destination 0x..."
                  />
                  <input value={withdrawAmount} onChange={(event) => setWithdrawAmount(event.target.value)} placeholder="Amount (ETH)" />
                </div>
                <div className="toolbar">
                  <button
                    type="button"
                    className="theme-toggle"
                    onClick={() =>
                      void runManagementAction(
                        () =>
                          managementPost('/api/v1/management/withdraw/destination', {
                            agentId,
                            chainKey: activeChainKey,
                            destination: withdrawDestination
                          }).then(() => Promise.resolve()),
                        'Withdraw destination saved.',
                        'withdraw'
                      )
                    }
                  >
                    Save Destination
                  </button>
                  <button
                    type="button"
                    className="theme-toggle"
                    onClick={() =>
                      void runManagementAction(
                        () =>
                          managementPost('/api/v1/management/withdraw', {
                            agentId,
                            chainKey: activeChainKey,
                            asset: 'ETH',
                            amount: withdrawAmount,
                            destination: withdrawDestination
                          }).then(() => Promise.resolve()),
                        'Withdraw request submitted.',
                        'withdraw'
                      )
                    }
                  >
                    Request Withdraw
                  </button>
                </div>
              </article>

              <article className="management-card">
                <h3>Policy Controls</h3>
                <div className="toolbar">
                  <label>
                    <span className="muted">Approval mode </span>
                    <select
                      value={policyApprovalMode}
                      onChange={(event) => setPolicyApprovalMode((event.target.value as 'per_trade' | 'auto') ?? 'per_trade')}
                    >
                      <option value="per_trade">per_trade</option>
                      <option value="auto">auto</option>
                    </select>
                  </label>
                </div>
                <div className="toolbar">
                  <label>
                    <input
                      type="checkbox"
                      checked={policyDailyCapUsdEnabled}
                      onChange={(event) => setPolicyDailyCapUsdEnabled(event.target.checked)}
                    />{' '}
                    Daily USD cap enabled
                  </label>
                  <label>
                    <input
                      type="checkbox"
                      checked={policyDailyTradeCapEnabled}
                      onChange={(event) => setPolicyDailyTradeCapEnabled(event.target.checked)}
                    />{' '}
                    Daily trade-count cap enabled
                  </label>
                </div>
                <div className="toolbar">
                  <input value={policyMaxTradeUsd} onChange={(event) => setPolicyMaxTradeUsd(event.target.value)} placeholder="Max Trade USD" />
                  <input
                    value={policyMaxDailyUsd}
                    onChange={(event) => setPolicyMaxDailyUsd(event.target.value)}
                    placeholder="Max Daily USD"
                    disabled={!policyDailyCapUsdEnabled}
                  />
                  <input
                    value={policyMaxDailyTradeCount}
                    onChange={(event) => setPolicyMaxDailyTradeCount(event.target.value.replace(/[^0-9]/g, ''))}
                    placeholder="Max Daily Trades"
                    disabled={!policyDailyTradeCapEnabled}
                  />
                </div>
                <div className="toolbar">
                  <input
                    value={policyAllowedTokensInput}
                    onChange={(event) => setPolicyAllowedTokensInput(event.target.value)}
                    placeholder="Comma-separated allowed token addresses"
                  />
                </div>
                <div className="toolbar">
                  <button
                    type="button"
                    className="theme-toggle"
                    onClick={() =>
                      void runManagementAction(
                        () =>
                          managementPost('/api/v1/management/policy/update', {
                            agentId,
                            mode: 'real',
                            approvalMode: policyApprovalMode,
                            maxTradeUsd: policyMaxTradeUsd,
                            maxDailyUsd: policyMaxDailyUsd,
                            dailyCapUsdEnabled: policyDailyCapUsdEnabled,
                            dailyTradeCapEnabled: policyDailyTradeCapEnabled,
                            maxDailyTradeCount: policyDailyTradeCapEnabled ? Number(policyMaxDailyTradeCount || '0') : null,
                            allowedTokens: policyAllowedTokensInput
                              .split(',')
                              .map((value) => value.trim())
                              .filter((value) => value.length > 0)
                          }).then(() => Promise.resolve()),
                        'Policy saved.',
                        'sensitive_action'
                      )
                    }
                  >
                    Save Policy
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
                            chainKey: activeChainKey,
                            scope: 'global',
                            action: 'grant',
                            maxAmountUsd: '50',
                            slippageBpsMax: 50,
                            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
                          }).then(() => Promise.resolve()),
                        'Global approval scope updated.',
                        'approval_scope_change'
                      )
                    }
                  >
                    Grant Global Approval
                  </button>
                </div>
              </article>

              <article className="management-card">
                <h3>Usage Progress</h3>
                <p className="muted">UTC day: {management.data.dailyUsage.utcDay}</p>
                <div className="usage-row">
                  <div className="muted">Used Today USD</div>
                  <div>
                    {management.data.dailyUsage.dailySpendUsd} / {policyDailyCapUsdEnabled ? policyMaxDailyUsd : 'No cap'}
                  </div>
                  <div className="usage-bar">
                    <div
                      className="usage-bar-fill"
                      style={{
                        width: `${usagePercent(
                          Number(management.data.dailyUsage.dailySpendUsd || '0'),
                          policyMaxDailyUsd,
                          policyDailyCapUsdEnabled
                        )}%`
                      }}
                    />
                  </div>
                </div>
                <div className="usage-row">
                  <div className="muted">Filled Trades Today</div>
                  <div>
                    {management.data.dailyUsage.dailyFilledTrades} / {policyDailyTradeCapEnabled ? policyMaxDailyTradeCount : 'No cap'}
                  </div>
                  <div className="usage-bar">
                    <div
                      className="usage-bar-fill"
                      style={{
                        width: `${usagePercent(
                          management.data.dailyUsage.dailyFilledTrades,
                          policyMaxDailyTradeCount,
                          policyDailyTradeCapEnabled
                        )}%`
                      }}
                    />
                  </div>
                </div>
              </article>

              <article className="management-card">
                <h3>Trading Operations</h3>
                {limitOrders.length === 0 ? <p className="muted">No limit orders.</p> : null}
                {limitOrders.map((item) => (
                  <div key={item.orderId} className="queue-item">
                    <div>
                      <strong>
                        {item.side.toUpperCase()} {item.amountIn}
                      </strong>
                      <div className="muted">{item.chainKey}</div>
                      <div className="muted">Status: {item.status}</div>
                      <div className="muted">
                        {shortenAddress(item.tokenIn)} {'->'} {shortenAddress(item.tokenOut)} @ {item.limitPrice}
                      </div>
                    </div>
                    {item.status === 'open' || item.status === 'triggered' ? (
                      <button
                        type="button"
                        className="theme-toggle"
                        onClick={() =>
                          void runManagementAction(
                            () =>
                              managementPost(`/api/v1/management/limit-orders/${item.orderId}/cancel`, { agentId }).then(() =>
                                Promise.resolve()
                              ),
                            `Cancelled ${item.orderId}`
                          )
                        }
                      >
                        Cancel
                      </button>
                    ) : null}
                  </div>
                ))}
                <p className="muted">Limit order creation is agent-driven. Owners can review and cancel orders here.</p>
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
                        disabled={!management.data.chainPolicy?.chainEnabled && item.chain_key === activeChainKey}
                        onClick={() =>
                          void runManagementAction(
                            () =>
                              managementPost('/api/v1/management/approvals/decision', {
                                agentId,
                                tradeId: item.trade_id,
                                decision: 'approve'
                              }).then(() => Promise.resolve()),
                            `Approved ${item.trade_id}`
                          )
                        }
                      >
                        Approve Trade
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
                        Reject Trade
                      </button>
                    </div>
                  </div>
                ))}
              </article>

              <article className="management-card">
                <details className="mgmt-details">
                  <summary>Management Audit Log</summary>
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
                </details>
              </article>
            </div>
          ) : null}
        </section>
      </aside>
    </div>
  );
}
