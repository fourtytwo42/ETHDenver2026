export const OFFDEX_TERMINAL_STATUSES = new Set([
  'settled',
  'cancelled',
  'expired',
  'failed'
]);

const OFFDEX_ALLOWED_TRANSITIONS = new Map<string, Set<string>>([
  ['proposed', new Set(['accepted', 'cancelled', 'expired', 'failed'])],
  ['accepted', new Set(['maker_funded', 'taker_funded', 'ready_to_settle', 'cancelled', 'expired', 'failed'])],
  ['maker_funded', new Set(['taker_funded', 'ready_to_settle', 'cancelled', 'expired', 'failed'])],
  ['taker_funded', new Set(['maker_funded', 'ready_to_settle', 'cancelled', 'expired', 'failed'])],
  ['ready_to_settle', new Set(['settling', 'cancelled', 'expired', 'failed'])],
  ['settling', new Set(['settled', 'failed'])],
  ['settled', new Set()],
  ['cancelled', new Set()],
  ['expired', new Set()],
  ['failed', new Set()]
]);

export type OffdexIntentRow = {
  status: string;
  maker_agent_id: string;
  taker_agent_id: string | null;
  expires_at: string;
  maker_fund_tx_hash: string | null;
  taker_fund_tx_hash: string | null;
};

export function isOffdexTerminalStatus(status: string): boolean {
  return OFFDEX_TERMINAL_STATUSES.has(status);
}

export function isAllowedOffdexTransition(fromStatus: string, toStatus: string): boolean {
  const allowed = OFFDEX_ALLOWED_TRANSITIONS.get(fromStatus);
  if (!allowed) {
    return false;
  }
  return allowed.has(toStatus);
}

export function isOffdexParticipant(row: OffdexIntentRow, agentId: string): boolean {
  return row.maker_agent_id === agentId || row.taker_agent_id === agentId;
}

export function isOffdexExpired(row: OffdexIntentRow, nowMs: number): boolean {
  if (isOffdexTerminalStatus(row.status)) {
    return false;
  }
  const expiresMs = new Date(row.expires_at).getTime();
  if (!Number.isFinite(expiresMs)) {
    return false;
  }
  return nowMs >= expiresMs;
}

export function canAcceptOffdexIntent(row: OffdexIntentRow, takerAgentId: string): boolean {
  if (row.status !== 'proposed') {
    return false;
  }
  if (row.maker_agent_id === takerAgentId) {
    return false;
  }
  if (row.taker_agent_id && row.taker_agent_id !== takerAgentId) {
    return false;
  }
  return true;
}

export function deriveFundingStatus(row: OffdexIntentRow): string {
  if (row.maker_fund_tx_hash && row.taker_fund_tx_hash) {
    return 'ready_to_settle';
  }
  if (row.maker_fund_tx_hash) {
    return 'maker_funded';
  }
  if (row.taker_fund_tx_hash) {
    return 'taker_funded';
  }
  return row.status;
}
