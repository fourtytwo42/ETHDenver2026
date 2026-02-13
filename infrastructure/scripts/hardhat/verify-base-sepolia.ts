import fs from 'node:fs';
import path from 'node:path';

import hre from 'hardhat';

const EXPECTED_CHAIN_ID = 84532;
const EXPLORER_BASE_URL = 'https://sepolia.basescan.org';

type DeployArtifact = {
  chainId: number;
  contracts: Record<'factory' | 'router' | 'quoter' | 'escrow', string>;
  deploymentTxHashes: Record<'factory' | 'router' | 'quoter' | 'escrow', string>;
};

function requireEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Missing required env var '${name}'.`);
  }
  return value;
}

function loadDeployArtifact(): DeployArtifact {
  const deployPath = path.join(process.cwd(), 'infrastructure', 'seed-data', 'base-sepolia-deploy.json');
  if (!fs.existsSync(deployPath)) {
    throw new Error(`Missing deploy artifact at ${deployPath}. Run hardhat:deploy-base-sepolia first.`);
  }
  return JSON.parse(fs.readFileSync(deployPath, 'utf-8')) as DeployArtifact;
}

function txLink(txHash: string): string {
  return `${EXPLORER_BASE_URL}/tx/${txHash}`;
}

async function main() {
  requireEnv('BASE_SEPOLIA_RPC_URL');
  requireEnv('BASE_SEPOLIA_DEPLOYER_PRIVATE_KEY');

  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  if (chainId !== EXPECTED_CHAIN_ID) {
    throw new Error(`Chain mismatch: expected ${EXPECTED_CHAIN_ID}, got ${chainId}.`);
  }

  const deployed = loadDeployArtifact();
  if (Number(deployed.chainId) !== EXPECTED_CHAIN_ID) {
    throw new Error(`Deploy artifact chainId mismatch: expected ${EXPECTED_CHAIN_ID}, got ${deployed.chainId}.`);
  }

  const codeChecks: Record<string, boolean> = {};
  for (const [name, address] of Object.entries(deployed.contracts)) {
    const code = await hre.ethers.provider.getCode(address);
    codeChecks[name] = code !== '0x';
  }

  const txChecks: Record<string, { hash: string; found: boolean; success: boolean; explorer: string }> = {};
  for (const [name, txHash] of Object.entries(deployed.deploymentTxHashes)) {
    const receipt = await hre.ethers.provider.getTransactionReceipt(txHash);
    txChecks[name] = {
      hash: txHash,
      found: receipt !== null,
      success: (receipt?.status ?? 0) === 1,
      explorer: txLink(txHash)
    };
  }

  const codeOk = Object.values(codeChecks).every(Boolean);
  const txOk = Object.values(txChecks).every((entry) => entry.found && entry.success);
  const ok = codeOk && txOk;

  const payload = {
    ok,
    verifiedAt: new Date().toISOString(),
    verifiedViaRpc: true,
    verifiedChainIdHex: `0x${chainId.toString(16)}`,
    verifiedContractCodePresent: codeChecks,
    verifiedDeploymentTransactions: txChecks
  };

  const outPath = path.join(process.cwd(), 'infrastructure', 'seed-data', 'base-sepolia-verify.json');
  fs.writeFileSync(outPath, JSON.stringify(payload, null, 2));
  console.log(JSON.stringify({ ...payload, outputPath: outPath }, null, 2));

  if (!ok) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(JSON.stringify({ ok: false, code: 'verify_failed', message: String(error) }, null, 2));
  process.exit(1);
});
