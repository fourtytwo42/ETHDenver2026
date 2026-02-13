import '@nomicfoundation/hardhat-ethers';
import type { HardhatUserConfig } from 'hardhat/config';

const config: HardhatUserConfig = {
  solidity: {
    version: '0.8.24',
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  paths: {
    sources: './infrastructure/contracts',
    tests: './infrastructure/tests',
    cache: './infrastructure/.hardhat-cache',
    artifacts: './infrastructure/.hardhat-artifacts'
  },
  networks: {
    localhost: {
      url: 'http://127.0.0.1:8545',
      chainId: 31337
    },
    hardhat: {
      chainId: 31337
    }
  }
};

export default config;
