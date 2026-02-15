import type { PoolClient } from 'pg';

export type ChainPolicyViolation = {
  code: 'chain_disabled';
  message: string;
  actionHint: string;
  details: Record<string, unknown>;
};

export async function getAgentChainEnabled(
  client: PoolClient,
  input: { agentId: string; chainKey: string }
): Promise<{ chainEnabled: boolean; updatedAt: string | null }> {
  const row = await client.query<{ chain_enabled: boolean; updated_at: string }>(
    `
    select chain_enabled, updated_at::text
    from agent_chain_policies
    where agent_id = $1
      and chain_key = $2
    limit 1
    `,
    [input.agentId, input.chainKey]
  );

  if ((row.rowCount ?? 0) === 0) {
    return { chainEnabled: true, updatedAt: null };
  }

  return { chainEnabled: Boolean(row.rows[0].chain_enabled), updatedAt: row.rows[0].updated_at ?? null };
}

export async function requireAgentChainEnabled(
  client: PoolClient,
  input: { agentId: string; chainKey: string }
): Promise<{ ok: true } | { ok: false; violation: ChainPolicyViolation }> {
  const policy = await getAgentChainEnabled(client, input);
  if (policy.chainEnabled) {
    return { ok: true };
  }

  return {
    ok: false,
    violation: {
      code: 'chain_disabled',
      message: `Trade blocked because chain '${input.chainKey}' is disabled by owner policy.`,
      actionHint: 'Enable the chain in the agent management page and retry.',
      details: { agentId: input.agentId, chainKey: input.chainKey, chainEnabled: false }
    }
  };
}

