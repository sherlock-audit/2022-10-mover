const ContractWhitelist = artifacts.require('ContractWhitelist');

const { deployProxy } = require('@openzeppelin/truffle-upgrades');

module.exports = async function (deployer, network, accounts) {
  let founderaddr = "";
  if (network == "live" || network == "live-fork") {
  } else if (network == "ropsten" || network == "ropsten-fork" /* for dry-run */) {
  } else if (network == "kovan" || network == "kovan-fork" /* for dry-run */) {
  } else if (network == "polygon" || network == "polygon-fork" /* for dry-run */) {
    founderaddr = "";
  } else {
    founderaddr = accounts[0];
  }

  if (founderaddr == '') {
    throw("ERROR: no address set for founder");
  }

  console.log("DEPLOYING ContractWhitelist, network=" + network);
  const registryInstance = await deployProxy(ContractWhitelist, [], { /*unsafeAllowCustomTypes: true,*/ from: founderaddr });
  console.log('ContractWhitelist deployed at address: ', registryInstance.address);

  // aftercare: add trusted registry contract addresses (swap aggregator proxies and bridge proxies used by app)
};
