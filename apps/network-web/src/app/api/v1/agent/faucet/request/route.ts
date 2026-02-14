import type { NextRequest } from 'next/server';

import { Wallet, JsonRpcProvider, Contract } from 'ethers';

import { requireAgentAuth } from '@/lib/agent-auth';
import { chainRpcUrl, getChainConfig } from '@/lib/chains';
import { dbQuery } from '@/lib/db';
import { errorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { enforceAgentFaucetDailyRateLimit } from '@/lib/rate-limit';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

const DRIP_WEI = '20000000000000000'; // 0.02 ETH
const DRIP_WETH_WEI = '10000000000000000000'; // 10.0 WETH (mock 18 decimals)
const DRIP_USDC_WEI = '20000000000000000000000'; // 20000.0 USDC (mock 18 decimals)

const ERC20_ABI = [
  'function balanceOf(address owner) view returns (uint256)',
  'function transfer(address to, uint256 value) returns (bool)'
];

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

    const agentId = auth.agentId;
    if (agentId === 'ag_slice7' || agentId.startsWith('ag_slice') || agentId.startsWith('ag_demo')) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Faucet is not available for demo agents.',
          actionHint: 'Register a non-demo agent with a real wallet address, then retry.'
        },
        requestId
      );
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
    const trimmedRecipient = recipient.trim();
    const lower = trimmedRecipient.toLowerCase();
    if (
      lower === '0x0000000000000000000000000000000000000000' ||
      lower === '0x1111111111111111111111111111111111111111'
    ) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Recipient wallet address is not eligible for faucet funds.',
          actionHint: 'Register a real agent wallet address and retry.'
        },
        requestId
      );
    }

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
    const faucetBalance = await provider.getBalance(signer.address);
    const dripAmount = BigInt(DRIP_WEI);
    if (faucetBalance < dripAmount) {
      return errorResponse(
        503,
        {
          code: 'internal_error',
          message: 'Faucet wallet has insufficient funds.',
          actionHint: 'Top up faucet wallet on base_sepolia, then retry.'
        },
        requestId
      );
    }

    // Token drips use chain config canonical token addresses. In Slice 21 this is expected to be
    // the X-Claw deployed mock WETH/USDC, not the canonical Base token addresses.
    const chainCfg = getChainConfig(chainKey);
    const wethAddr = (chainCfg?.canonicalTokens?.WETH || '').trim();
    const usdcAddr = (chainCfg?.canonicalTokens?.USDC || '').trim();
    if (!wethAddr || !usdcAddr) {
      return errorResponse(
        503,
        {
          code: 'internal_error',
          message: 'Faucet token addresses are not configured for this chain.',
          actionHint: 'Configure chain canonicalTokens.WETH and canonicalTokens.USDC for base_sepolia.'
        },
        requestId
      );
    }

    const weth = new Contract(wethAddr, ERC20_ABI, signer);
    const usdc = new Contract(usdcAddr, ERC20_ABI, signer);
    const dripWeth = BigInt(DRIP_WETH_WEI);
    const dripUsdc = BigInt(DRIP_USDC_WEI);
    const [wethBal, usdcBal] = (await Promise.all([
      weth.balanceOf(signer.address) as Promise<bigint>,
      usdc.balanceOf(signer.address) as Promise<bigint>
    ])) as [bigint, bigint];
    if (wethBal < dripWeth || usdcBal < dripUsdc) {
      return errorResponse(
        503,
        {
          code: 'internal_error',
          message: 'Faucet token balance is insufficient.',
          actionHint: 'Top up faucet token balances (WETH/USDC) and retry.',
          details: {
            wethAddress: wethAddr,
            usdcAddress: usdcAddr
          }
        },
        requestId
      );
    }

    const limiter = await enforceAgentFaucetDailyRateLimit(requestId, auth.agentId, chainKey);
    if (!limiter.ok) {
      return limiter.response;
    }

    const txWeth = await weth.transfer(trimmedRecipient, dripWeth);
    const txUsdc = await usdc.transfer(trimmedRecipient, dripUsdc);
    const tx = await signer.sendTransaction({
      to: trimmedRecipient,
      value: dripAmount
    });

    return successResponse(
      {
        ok: true,
        agentId: auth.agentId,
        chainKey,
        amountWei: DRIP_WEI,
        to: trimmedRecipient,
        txHash: tx.hash,
        tokenDrips: [
          { token: 'WETH', tokenAddress: wethAddr, amountWei: DRIP_WETH_WEI, txHash: txWeth.hash },
          { token: 'USDC', tokenAddress: usdcAddr, amountWei: DRIP_USDC_WEI, txHash: txUsdc.hash }
        ]
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
