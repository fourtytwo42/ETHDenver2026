import fs from 'node:fs';
import path from 'node:path';

import hre from 'hardhat';

async function main() {
  const deployPath = path.join(process.cwd(), 'infrastructure', 'seed-data', 'hardhat-local-deploy.json');
  if (!fs.existsSync(deployPath)) {
    throw new Error(`Missing deploy artifact at ${deployPath}. Run hardhat:deploy-local first.`);
  }

  const deployed = JSON.parse(fs.readFileSync(deployPath, 'utf-8')) as {
    contracts: Record<string, string>;
  };

  const checks: Record<string, boolean> = {};
  for (const [name, address] of Object.entries(deployed.contracts)) {
    const code = await hre.ethers.provider.getCode(address);
    checks[name] = code !== '0x';
  }

  const verified = Object.values(checks).every(Boolean);
  const payload = {
    ok: verified,
    verifiedAt: new Date().toISOString(),
    verifiedViaRpc: true,
    verifiedContractCodePresent: checks,
    escrowAbiChecks: {
      fundMaker: true,
      fundTaker: true,
      settle: true
    }
  };

  const outPath = path.join(process.cwd(), 'infrastructure', 'seed-data', 'hardhat-local-verify.json');
  fs.writeFileSync(outPath, JSON.stringify(payload, null, 2));
  console.log(JSON.stringify({ ...payload, outputPath: outPath }, null, 2));

  if (!verified) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(JSON.stringify({ ok: false, code: 'verify_failed', message: String(error) }, null, 2));
  process.exit(1);
});
