import assert from 'node:assert/strict';

import hre from 'hardhat';

function feeFromGross(gross: bigint): bigint {
  return (gross * 50n) / 10000n;
}

describe('XClawFeeRouterV2', function () {
  it('getAmountsOut returns net (post-fee) amounts', async function () {
    const [deployer] = await hre.ethers.getSigners();

    const MockRouter = await hre.ethers.getContractFactory('MockRouter');
    const dexRouter = await MockRouter.deploy();
    await dexRouter.waitForDeployment();

    const initialSupply = hre.ethers.parseEther('10000000');
    const MockERC20 = await hre.ethers.getContractFactory('MockERC20');
    const weth = await MockERC20.deploy('Wrapped Ether', 'WETH', initialSupply, deployer.address);
    await weth.waitForDeployment();
    const usdc = await MockERC20.deploy('USD Coin', 'USDC', initialSupply, deployer.address);
    await usdc.waitForDeployment();

    // Configure router to treat these addresses as WETH/USDC and use default 2000 price.
    await (await dexRouter.setTokenPair(await weth.getAddress(), await usdc.getAddress())).wait();

    // Seed router output balance so it can pay swaps.
    await (await usdc.mint(await dexRouter.getAddress(), hre.ethers.parseEther('50000000'))).wait();

    const XClawFeeRouterV2 = await hre.ethers.getContractFactory('XClawFeeRouterV2');
    const proxy = await XClawFeeRouterV2.deploy(await dexRouter.getAddress(), deployer.address);
    await proxy.waitForDeployment();

    const amountIn = hre.ethers.parseEther('1');
    const path = [await weth.getAddress(), await usdc.getAddress()];

    const gross = await dexRouter.getAmountsOut(amountIn, path);
    const net = await proxy.getAmountsOut(amountIn, path);

    assert.equal(gross.length, 2);
    assert.equal(net.length, 2);
    assert.equal(net[0], gross[0]);

    const grossOut = gross[1];
    const expectedNetOut = grossOut - feeFromGross(grossOut);
    assert.equal(net[1], expectedNetOut);
  });

  it('swapExactTokensForTokens charges exactly 50 bps on output and forwards net to recipient', async function () {
    const [deployer, user] = await hre.ethers.getSigners();

    const MockRouter = await hre.ethers.getContractFactory('MockRouter');
    const dexRouter = await MockRouter.deploy();
    await dexRouter.waitForDeployment();

    const initialSupply = hre.ethers.parseEther('10000000');
    const MockERC20 = await hre.ethers.getContractFactory('MockERC20');
    const weth = await MockERC20.deploy('Wrapped Ether', 'WETH', initialSupply, user.address);
    await weth.waitForDeployment();
    const usdc = await MockERC20.deploy('USD Coin', 'USDC', initialSupply, deployer.address);
    await usdc.waitForDeployment();

    await (await dexRouter.setTokenPair(await weth.getAddress(), await usdc.getAddress())).wait();
    await (await usdc.mint(await dexRouter.getAddress(), hre.ethers.parseEther('50000000'))).wait();

    const treasury = deployer.address;
    const XClawFeeRouterV2 = await hre.ethers.getContractFactory('XClawFeeRouterV2');
    const proxy = await XClawFeeRouterV2.deploy(await dexRouter.getAddress(), treasury);
    await proxy.waitForDeployment();

    const amountIn = hre.ethers.parseEther('1');
    const path = [await weth.getAddress(), await usdc.getAddress()];
    const deadline = BigInt(Math.floor(Date.now() / 1000) + 600);

    // user approves proxy to pull WETH
    await (await weth.connect(user).approve(await proxy.getAddress(), amountIn)).wait();

    const grossQuote = await dexRouter.getAmountsOut(amountIn, path);
    const grossOut = grossQuote[1];
    const fee = feeFromGross(grossOut);
    const expectedNet = grossOut - fee;

    const userBefore = await usdc.balanceOf(user.address);
    const treasuryBefore = await usdc.balanceOf(treasury);

    const tx = await proxy.connect(user).swapExactTokensForTokens(amountIn, expectedNet, path, user.address, deadline);
    await tx.wait();

    const userAfter = await usdc.balanceOf(user.address);
    const treasuryAfter = await usdc.balanceOf(treasury);

    assert.equal(userAfter - userBefore, expectedNet);
    assert.equal(treasuryAfter - treasuryBefore, fee);
  });

  it('slippage check uses net semantics (amountOutMin is net-to-user)', async function () {
    const [deployer, user] = await hre.ethers.getSigners();

    const MockRouter = await hre.ethers.getContractFactory('MockRouter');
    const dexRouter = await MockRouter.deploy();
    await dexRouter.waitForDeployment();

    const initialSupply = hre.ethers.parseEther('10000000');
    const MockERC20 = await hre.ethers.getContractFactory('MockERC20');
    const weth = await MockERC20.deploy('Wrapped Ether', 'WETH', initialSupply, user.address);
    await weth.waitForDeployment();
    const usdc = await MockERC20.deploy('USD Coin', 'USDC', initialSupply, deployer.address);
    await usdc.waitForDeployment();

    await (await dexRouter.setTokenPair(await weth.getAddress(), await usdc.getAddress())).wait();
    await (await usdc.mint(await dexRouter.getAddress(), hre.ethers.parseEther('50000000'))).wait();

    const XClawFeeRouterV2 = await hre.ethers.getContractFactory('XClawFeeRouterV2');
    const proxy = await XClawFeeRouterV2.deploy(await dexRouter.getAddress(), deployer.address);
    await proxy.waitForDeployment();

    const amountIn = hre.ethers.parseEther('1');
    const path = [await weth.getAddress(), await usdc.getAddress()];
    const deadline = BigInt(Math.floor(Date.now() / 1000) + 600);

    await (await weth.connect(user).approve(await proxy.getAddress(), amountIn)).wait();

    const grossQuote = await dexRouter.getAmountsOut(amountIn, path);
    const grossOut = grossQuote[1];
    const fee = feeFromGross(grossOut);
    const netOut = grossOut - fee;

    // Using gross as min should revert since user receives net < gross.
    let reverted = false;
    try {
      const t = await proxy.connect(user).swapExactTokensForTokens(amountIn, grossOut, path, user.address, deadline);
      await t.wait();
    } catch (e) {
      const msg = String(e);
      assert.ok(msg.includes('SLIPPAGE_NET'));
      reverted = true;
    }
    assert.equal(reverted, true);

    // Using net as min should pass.
    const okTx = await proxy.connect(user).swapExactTokensForTokens(amountIn, netOut, path, user.address, deadline);
    await okTx.wait();
  });
});

