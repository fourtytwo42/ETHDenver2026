import type { NextRequest } from 'next/server';

import { Wallet, JsonRpcProvider } from 'ethers';

import { requireAgentAuth } from '@/lib/agent-auth';
import { chainRpcUrl } from '@/lib/chains';
import { dbQuery } from '@/lib/db';
import { errorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { enforceAgentFaucetDailyRateLimit } from '@/lib/rate-limit';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

const DRIP_WEI = '50000000000000000'; // 0.05 ETH

type AgentFaucetRequest = {
  schemaVersion: number;
  agentId: string;
  chainKey?: string;
};

export async function POST(req: NextRequest) {
  const requestId = getRequestId(req);

  try {
    const parsed = await parseJsonBody(req, requestId);
    if (!parsed.ok) {
      return parsed.response;
    }

    const validated = validatePayload<AgentFaucetRequest>('agent-faucet-request.schema.json', parsed.body);
    if (!validated.ok) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Faucet request payload does not match schema.',
          actionHint: 'Provide schemaVersion and agentId. chainKey is optional.',
          details: validated.details
        },
        requestId
      );
    }

    const body = validated.data;
    const auth = requireAgentAuth(req, body.agentId, requestId);
    if (!auth.ok) {
      return auth.response;
    }

    const chainKey = (body.chainKey || 'base_sepolia').trim();
    if (chainKey !== 'base_sepolia') {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Faucet is only available on base_sepolia.',
          actionHint: 'Retry with chainKey=base_sepolia.'
        },
        requestId
      );
    }

    const limiter = await enforceAgentFaucetDailyRateLimit(requestId, auth.agentId, chainKey);
    if (!limiter.ok) {
      return limiter.response;
    }

    const faucetPrivateKey = (process.env.XCLAW_TESTNET_FAUCET_PRIVATE_KEY || '').trim();
    if (!faucetPrivateKey) {
      return errorResponse(
        503,
        {
          code: 'internal_error',
          message: 'Faucet is not configured.',
          actionHint: 'Set XCLAW_TESTNET_FAUCET_PRIVATE_KEY on the server.'
        },
        requestId
      );
    }

    const walletResult = await dbQuery<{ address: string }>(
      `
      select address
      from agent_wallets
      where agent_id = $1
        and chain_key = $2
      limit 1
      `,
      [auth.agentId, chainKey]
    );
    if ((walletResult.rowCount ?? 0) === 0) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Agent wallet is not registered for requested chain.',
          actionHint: 'Register agent wallet on base_sepolia and retry.'
        },
        requestId
      );
    }

    const recipient = walletResult.rows[0].address;
    const rpcUrl = (process.env.XCLAW_TESTNET_FAUCET_RPC_URL || '').trim() || chainRpcUrl(chainKey);
    if (!rpcUrl) {
      return errorResponse(
        503,
        {
          code: 'internal_error',
          message: 'Faucet RPC is not configured.',
          actionHint: 'Set XCLAW_TESTNET_FAUCET_RPC_URL or configure chain RPC.'
        },
        requestId
      );
    }

    const provider = new JsonRpcProvider(rpcUrl);
    const signer = new Wallet(faucetPrivateKey, provider);
    const tx = await signer.sendTransaction({
      to: recipient,
      value: BigInt(DRIP_WEI)
    });

    return successResponse(
      {
        ok: true,
        agentId: auth.agentId,
        chainKey,
        amountWei: DRIP_WEI,
        to: recipient,
        txHash: tx.hash
      },
      200,
      requestId
    );
  } catch (error) {
    return errorResponse(
      500,
      {
        code: 'internal_error',
        message: error instanceof Error ? error.message : 'Faucet request failed.',
        actionHint: 'Retry later or check faucet funding/configuration.'
      },
      requestId
    );
  }
}
