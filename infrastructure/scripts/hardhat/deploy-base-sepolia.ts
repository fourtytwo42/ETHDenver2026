import fs from 'node:fs';
import path from 'node:path';

import hre from 'hardhat';

const EXPECTED_CHAIN_ID = 84532;
const EXPLORER_BASE_URL = 'https://sepolia.basescan.org';
const DEFAULT_ETH_USD = '2000';

function requireEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Missing required env var '${name}'.`);
  }
  return value;
}

function parseDecimalToE18(value: string): bigint {
  const raw = value.trim();
  if (!raw) {
    throw new Error('empty decimal');
  }
  const neg = raw.startsWith('-');
  const s = neg ? raw.slice(1) : raw;
  const [whole, frac = ''] = s.split('.');
  const wholeNorm = whole.length ? whole : '0';
  const fracNorm = (frac || '').slice(0, 18).padEnd(18, '0');
  const out = BigInt(wholeNorm) * 10n ** 18n + BigInt(fracNorm || '0');
  return neg ? -out : out;
}

async function fetchEthUsdPrice(): Promise<{ priceUsd: string; source: string; ok: boolean }> {
  // Best-effort external quote for seeding mock DEX liquidity. This does not affect security boundaries.
  const fallback = { priceUsd: DEFAULT_ETH_USD, source: 'fallback', ok: false };
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2500);
    const res = await fetch('https://api.coinbase.com/v2/prices/ETH-USD/spot', {
      method: 'GET',
      headers: { 'accept': 'application/json' },
      signal: controller.signal
    });
    clearTimeout(timeout);
    if (!res.ok) {
      return fallback;
    }
    const json = (await res.json()) as { data?: { amount?: string } };
    const amount = json?.data?.amount?.trim();
    if (!amount) {
      return fallback;
    }
    // Sanity clamp to avoid totally bogus values.
    const n = Number(amount);
    if (!Number.isFinite(n) || n < 50 || n > 50000) {
      return fallback;
    }
    return { priceUsd: amount, source: 'coinbase', ok: true };
  } catch {
    return fallback;
  }
}

function txHashOf(contract: { deploymentTransaction: () => { hash: string } | null }, label: string): string {
  const tx = contract.deploymentTransaction();
  if (!tx?.hash) {
    throw new Error(`Missing deployment transaction hash for ${label}.`);
  }
  return tx.hash;
}

function txLink(txHash: string): string {
  return `${EXPLORER_BASE_URL}/tx/${txHash}`;
}

async function main() {
  const rpcUrl = requireEnv('BASE_SEPOLIA_RPC_URL');
  requireEnv('BASE_SEPOLIA_DEPLOYER_PRIVATE_KEY');
  const basescanApiKeyConfigured = Boolean(process.env.BASESCAN_API_KEY?.trim());
  const faucetAddress = (process.env.XCLAW_TESTNET_FAUCET_ADDRESS || '').trim();

  const [deployer] = await hre.ethers.getSigners();
  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  if (chainId !== EXPECTED_CHAIN_ID) {
    throw new Error(`Chain mismatch: expected ${EXPECTED_CHAIN_ID}, got ${chainId}.`);
  }

  const MockFactory = await hre.ethers.getContractFactory('MockFactory');
  const factory = await MockFactory.deploy();
  await factory.waitForDeployment();

  const MockRouter = await hre.ethers.getContractFactory('MockRouter');
  const router = await MockRouter.deploy();
  await router.waitForDeployment();

  const MockQuoter = await hre.ethers.getContractFactory('MockQuoter');
  const quoter = await MockQuoter.deploy();
  await quoter.waitForDeployment();

  const MockEscrow = await hre.ethers.getContractFactory('MockEscrow');
  const escrow = await MockEscrow.deploy();
  await escrow.waitForDeployment();

  // Deploy mock tokens for Base Sepolia trading so agents can trade without wrapping scarce testnet ETH.
  // NOTE: these are 18-decimal mock tokens (including "USDC") for consistency with existing runtime math.
  const initialSupply = hre.ethers.parseEther('5000000');
  const MockERC20 = await hre.ethers.getContractFactory('MockERC20');
  const weth = await MockERC20.deploy('Wrapped Ether', 'WETH', initialSupply, deployer.address);
  await weth.waitForDeployment();
  const usdc = await MockERC20.deploy('USD Coin', 'USDC', initialSupply, deployer.address);
  await usdc.waitForDeployment();

  const price = await fetchEthUsdPrice();
  const priceE18 = parseDecimalToE18(price.priceUsd);
  await (await router.setEthUsdPriceE18(priceE18)).wait();
  await (await router.setTokenPair(await weth.getAddress(), await usdc.getAddress())).wait();

  // Seed mock router balances to act as "liquidity" for the simplistic swap adapter.
  // Target: $1,000,000 USDC and equivalent WETH at current ETH/USD.
  const seedUsdc = hre.ethers.parseEther('1000000');
  const seedWeth = (seedUsdc * 10n ** 18n) / priceE18; // WETH = USDC / (USD per ETH)

  await (await usdc.transfer(await router.getAddress(), seedUsdc)).wait();
  await (await weth.transfer(await router.getAddress(), seedWeth)).wait();

  // Optional: seed the faucet wallet with drippable token balances (so server can transfer without minting).
  if (faucetAddress) {
    const faucetUsdc = hre.ethers.parseEther('2000000');
    const faucetWeth = hre.ethers.parseEther('2000');
    await (await usdc.transfer(faucetAddress, faucetUsdc)).wait();
    await (await weth.transfer(faucetAddress, faucetWeth)).wait();
  }

  const deployedAt = new Date().toISOString();
  const txHashes = {
    factory: txHashOf(factory, 'factory'),
    router: txHashOf(router, 'router'),
    quoter: txHashOf(quoter, 'quoter'),
    escrow: txHashOf(escrow, 'escrow')
  };
  const addresses = {
    factory: await factory.getAddress(),
    router: await router.getAddress(),
    quoter: await quoter.getAddress(),
    escrow: await escrow.getAddress(),
    WETH: await weth.getAddress(),
    USDC: await usdc.getAddress()
  };

  const deployResult = {
    ok: true,
    chainId,
    network: 'base_sepolia',
    deployedAt,
    deployer: deployer.address,
    rpcUrlFingerprint: `${rpcUrl.slice(0, 24)}...`,
    contracts: addresses,
    deploymentTxHashes: txHashes,
    explorerLinks: {
      factory: txLink(txHashes.factory),
      router: txLink(txHashes.router),
      quoter: txLink(txHashes.quoter),
      escrow: txLink(txHashes.escrow)
    },
    seeded: {
      ethUsdPrice: {
        value: price.priceUsd,
        source: price.source,
        usedFallback: !price.ok
      },
      routerBalances: {
        USDC: seedUsdc.toString(),
        WETH: seedWeth.toString()
      },
      faucetAddress: faucetAddress || null
    },
    sourceVerification: {
      provider: 'basescan',
      apiKeyConfigured: basescanApiKeyConfigured
    }
  };

  const outPath = path.join(process.cwd(), 'infrastructure', 'seed-data', 'base-sepolia-deploy.json');
  fs.writeFileSync(outPath, JSON.stringify(deployResult, null, 2));
  console.log(JSON.stringify({ ...deployResult, outputPath: outPath }, null, 2));
}

main().catch((error) => {
  console.error(JSON.stringify({ ok: false, code: 'deploy_failed', message: String(error) }, null, 2));
  process.exit(1);
});
