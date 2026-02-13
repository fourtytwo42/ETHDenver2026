import fs from 'node:fs';
import path from 'node:path';

import hre from 'hardhat';

const EXPECTED_CHAIN_ID = 84532;
const EXPLORER_BASE_URL = 'https://sepolia.basescan.org';

function requireEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Missing required env var '${name}'.`);
  }
  return value;
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
    escrow: await escrow.getAddress()
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
