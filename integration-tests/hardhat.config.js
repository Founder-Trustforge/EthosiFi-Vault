module.exports = {
  solidity: '0.8.28',
  networks: { hardhat: { hardfork: 'cancun', allowUnlimitedContractSize: true, blockGasLimit: 60_000_000, initialBaseFeePerGas: 0, accounts: { count: 20 }, mining: { auto: true } } },
};
