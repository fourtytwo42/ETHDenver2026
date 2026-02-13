import fs from 'node:fs';
import path from 'node:path';

import hre from 'hardhat';

async function main() {
  const [deployer] = await hre.ethers.getSigners();

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

  const initialSupply = hre.ethers.parseEther('1000000');
  const MockERC20 = await hre.ethers.getContractFactory('MockERC20');
  const weth = await MockERC20.deploy('Wrapped Ether', 'WETH', initialSupply, deployer.address);
  await weth.waitForDeployment();
  const usdc = await MockERC20.deploy('USD Coin', 'USDC', initialSupply, deployer.address);
  await usdc.waitForDeployment();

  // Provide output liquidity for the simplistic 1:1 mock router swap.
  await (await usdc.mint(await router.getAddress(), hre.ethers.parseEther('500000'))).wait();

  const deployResult = {
    ok: true,
    chainId: Number((await hre.ethers.provider.getNetwork()).chainId),
    deployedAt: new Date().toISOString(),
    deployer: deployer.address,
    contracts: {
      factory: await factory.getAddress(),
      router: await router.getAddress(),
      quoter: await quoter.getAddress(),
      escrow: await escrow.getAddress(),
      WETH: await weth.getAddress(),
      USDC: await usdc.getAddress()
    },
    escrowCapabilities: {
      openDeal: true,
      fundMaker: true,
      fundTaker: true,
      settle: true
    }
  };

  const outPath = path.join(process.cwd(), 'infrastructure', 'seed-data', 'hardhat-local-deploy.json');
  fs.writeFileSync(outPath, JSON.stringify(deployResult, null, 2));
  console.log(JSON.stringify({ ...deployResult, outputPath: outPath }, null, 2));
}

main().catch((error) => {
  console.error(JSON.stringify({ ok: false, code: 'deploy_failed', message: String(error) }, null, 2));
  process.exit(1);
});
