import type { NextRequest } from 'next/server';

import { dbQuery } from '@/lib/db';
import { errorResponse, internalErrorResponse, successResponse } from '@/lib/errors';
import { getRequestId } from '@/lib/request-id';

export const runtime = 'nodejs';

export async function GET(
  req: NextRequest,
  context: { params: Promise<{ agentId: string }> }
) {
  const requestId = getRequestId(req);

  try {
    const { agentId } = await context.params;

    const agent = await dbQuery<{
      agent_id: string;
      agent_name: string;
      description: string | null;
      owner_label: string | null;
      runtime_platform: string;
      public_status: string;
      created_at: string;
      updated_at: string;
      last_activity_at: string | null;
    }>(
      `
      select
        a.agent_id,
        a.agent_name,
        a.description,
        a.owner_label,
        a.runtime_platform,
        a.public_status,
        a.created_at::text,
        a.updated_at::text,
        (
          select max(ev.created_at)::text
          from agent_events ev
          where ev.agent_id = a.agent_id
        ) as last_activity_at
      from agents a
      where a.agent_id = $1
      limit 1
      `,
      [agentId]
    );

    if (agent.rowCount === 0) {
      return errorResponse(
        404,
        {
          code: 'payload_invalid',
          message: 'Agent profile not found.',
          actionHint: 'Verify agentId and retry.'
        },
        requestId
      );
    }

    const wallets = await dbQuery<{
      chain_key: string;
      address: string;
      custody: string;
    }>(
      `
      select chain_key, address, custody
      from agent_wallets
      where agent_id = $1
      order by chain_key asc
      `,
      [agentId]
    );

    const metrics = await dbQuery<{
      window: string;
      pnl_usd: string | null;
      return_pct: string | null;
      volume_usd: string | null;
      trades_count: number;
      followers_count: number;
      created_at: string;
    }>(
      `
      select
        "window" as window,
        pnl_usd::text,
        return_pct::text,
        volume_usd::text,
        trades_count,
        followers_count,
        created_at::text
      from performance_snapshots
      where agent_id = $1
      order by created_at desc
      limit 1
      `,
      [agentId]
    );

    const offdexHistory = await dbQuery<{
      settlement_intent_id: string;
      chain_key: string;
      role: string;
      status: string;
      maker_token: string;
      taker_token: string;
      escrow_contract: string;
      maker_fund_tx_hash: string | null;
      taker_fund_tx_hash: string | null;
      settlement_tx_hash: string | null;
      created_at: string;
      updated_at: string;
    }>(
      `
      select
        settlement_intent_id,
        chain_key,
        case when maker_agent_id = $1 then 'maker' else 'taker' end as role,
        status,
        maker_token,
        taker_token,
        escrow_contract,
        maker_fund_tx_hash,
        taker_fund_tx_hash,
        settlement_tx_hash,
        created_at::text,
        updated_at::text
      from offdex_settlement_intents
      where maker_agent_id = $1 or taker_agent_id = $1
      order by created_at desc
      limit 25
      `,
      [agentId]
    );

    return successResponse(
      {
        ok: true,
        agent: agent.rows[0],
        wallets: wallets.rows,
        latestMetrics: metrics.rows[0] ?? null,
        offdexHistory: offdexHistory.rows.map((row) => ({
          settlementIntentId: row.settlement_intent_id,
          chainKey: row.chain_key,
          role: row.role,
          status: row.status,
          pairLabel: `${row.maker_token.slice(0, 10)}.../${row.taker_token.slice(0, 10)}...`,
          escrowContract: row.escrow_contract,
          makerFundTxHash: row.maker_fund_tx_hash,
          takerFundTxHash: row.taker_fund_tx_hash,
          settlementTxHash: row.settlement_tx_hash,
          createdAt: row.created_at,
          updatedAt: row.updated_at
        }))
      },
      200,
      requestId
    );
  } catch {
    return internalErrorResponse(requestId);
  }
}
