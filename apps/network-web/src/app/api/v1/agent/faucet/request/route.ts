import type { NextRequest } from 'next/server';

import { Wallet, JsonRpcProvider, Contract, isAddress } from 'ethers';

import { requireAgentAuth } from '@/lib/agent-auth';
import { chainRpcUrl, getChainConfig } from '@/lib/chains';
import { dbQuery } from '@/lib/db';
import { errorResponse, successResponse } from '@/lib/errors';
import { parseJsonBody } from '@/lib/http';
import { enforceAgentFaucetDailyRateLimit } from '@/lib/rate-limit';
import { getRedisClient } from '@/lib/redis';
import { getRequestId } from '@/lib/request-id';
import { validatePayload } from '@/lib/validation';

export const runtime = 'nodejs';

const DRIP_WEI = '20000000000000000'; // 0.02 ETH
const DRIP_WETH_WEI = '10000000000000000000'; // 10.0 WETH (mock 18 decimals)
const DRIP_USDC_WEI = '20000000000000000000000'; // 20000.0 USDC (mock 18 decimals)
// Rough buffer to ensure we don't attempt drips when the faucet can't cover gas (EIP-1559 spikes, 3 txs).
// This is not a guarantee, but prevents the common "insufficient funds for gas + value" failure mode.
const GAS_BUFFER_MULTIPLIER_BPS = 12000; // 1.2x

const ERC20_ABI = [
  'function balanceOf(address owner) view returns (uint256)',
  'function transfer(address to, uint256 value) returns (bool)'
];

function faucetDailyRedisKey(agentId: string, chainKey: string, now: Date): { redisKey: string; ttlSeconds: number } {
  // Must match enforceAgentFaucetDailyRateLimit() key derivation.
  const nextUtcMidnight = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 0, 0);
  const ttlSeconds = Math.max(1, Math.floor((nextUtcMidnight - now.getTime()) / 1000));
  const keyDate = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}-${String(now.getUTCDate()).padStart(2, '0')}`;
  const redisKey = `xclaw:ratelimit:v1:agent_faucet_daily:${agentId}:${chainKey}:${keyDate}`;
  return { redisKey, ttlSeconds };
}

async function rollbackFaucetDailyLimit(agentId: string, chainKey: string): Promise<void> {
  try {
    const now = new Date();
    const { redisKey } = faucetDailyRedisKey(agentId, chainKey, now);
    const redis = await getRedisClient();
    await redis.del(redisKey);
  } catch {
    // Best-effort: if Redis is down, limiter already fails open anyway.
  }
}

function buildFeeOverrides(
  feeData: Awaited<ReturnType<JsonRpcProvider['getFeeData']>>,
  attempt: number
): { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint } {
  // Bump strategy: +1 gwei maxPriority per attempt; maxFee follows maxFee or gasPrice with a buffer.
  const bumpGwei = BigInt(1_000_000_000) * BigInt(attempt);
  const basePriority = feeData.maxPriorityFeePerGas ?? BigInt(1_000_000_000); // 1 gwei fallback
  const maxPriorityFeePerGas = basePriority + bumpGwei;
  const baseMaxFee = feeData.maxFeePerGas ?? feeData.gasPrice ?? BigInt(2_000_000_000); // 2 gwei fallback
  const maxFeePerGas = baseMaxFee + bumpGwei + BigInt(2_000_000_000);
  return { maxFeePerGas, maxPriorityFeePerGas };
}

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
    if (!isAddress(trimmedRecipient)) {
      return errorResponse(
        400,
        {
          code: 'payload_invalid',
          message: 'Agent wallet address is not a valid EVM address.',
          actionHint: 'Re-register the agent wallet address and retry.'
        },
        requestId
      );
    }
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
    const dripAmount = BigInt(DRIP_WEI);

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

    // Ensure faucet has enough ETH to cover value transfer + gas for all 3 txs (2 ERC20 + 1 ETH).
    const faucetBalance = await provider.getBalance(signer.address);
    const feeData = await provider.getFeeData();
    const maxFeePerGas = feeData.maxFeePerGas ?? feeData.gasPrice ?? BigInt('1000000000'); // 1 gwei fallback

    // Estimate gas for transfers; this is best-effort and may differ slightly at execution time.
    const [gasWeth, gasUsdc, gasEth] = await Promise.all([
      signer.estimateGas(await weth.transfer.populateTransaction(trimmedRecipient, dripWeth)),
      signer.estimateGas(await usdc.transfer.populateTransaction(trimmedRecipient, dripUsdc)),
      signer.estimateGas({ to: trimmedRecipient, value: dripAmount })
    ]);

    const gasSum = gasWeth + gasUsdc + gasEth;
    const gasCost = (gasSum * maxFeePerGas * BigInt(GAS_BUFFER_MULTIPLIER_BPS)) / BigInt(10000);
    const requiredEth = dripAmount + gasCost;
    if (faucetBalance < requiredEth) {
      return errorResponse(
        503,
        {
          code: 'internal_error',
          message: 'Faucet wallet has insufficient ETH to cover drip plus gas.',
          actionHint: 'Top up faucet wallet on base_sepolia, then retry.',
          details: {
            faucetAddress: signer.address,
            requiredWei: requiredEth.toString(),
            balanceWei: faucetBalance.toString()
          }
        },
        requestId
      );
    }

    const limiter = await enforceAgentFaucetDailyRateLimit(requestId, auth.agentId, chainKey);
    if (!limiter.ok) {
      return limiter.response;
    }

    // Use explicit nonces from "pending" so we don't accidentally try to reuse a nonce when
    // the faucet wallet has stuck pending transactions (common cause of replacement-underpriced).
    const baseNonce = await provider.getTransactionCount(signer.address, 'pending');
    const sendAttempts = 3;
    let txWeth: { hash: string } | null = null;
    let txUsdc: { hash: string } | null = null;
    let tx: { hash: string } | null = null;

    try {
      for (let attempt = 0; attempt < sendAttempts; attempt += 1) {
        const fees = buildFeeOverrides(feeData, attempt);
        try {
          txWeth = (await weth.transfer(trimmedRecipient, dripWeth, { nonce: baseNonce, ...fees })) as { hash: string };
          txUsdc = (await usdc.transfer(trimmedRecipient, dripUsdc, { nonce: baseNonce + 1, ...fees })) as { hash: string };
          tx = (await signer.sendTransaction({
            to: trimmedRecipient,
            value: dripAmount,
            nonce: baseNonce + 2,
            ...fees
          })) as { hash: string };
          break;
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          const retryable =
            msg.includes('REPLACEMENT_UNDERPRICED') ||
            msg.includes('replacement transaction underpriced') ||
            msg.includes('nonce too low') ||
            msg.includes('already known');
          if (attempt < sendAttempts - 1 && retryable) {
            continue;
          }
          throw err;
        }
      }
    } catch (sendError) {
      // Do not burn daily limiter on send failure (mempool/nonce issues, RPC flakiness, etc).
      await rollbackFaucetDailyLimit(auth.agentId, chainKey);
      throw sendError;
    }
    if (!txWeth || !txUsdc || !tx) {
      await rollbackFaucetDailyLimit(auth.agentId, chainKey);
      throw new Error('Faucet send failed (no tx hashes).');
    }

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
