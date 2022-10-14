const HardenedTopupProxy = artifacts.require('HardenedTopupProxy');

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

  console.log("DEPLOYING HardenedTopupProxy, network=" + network);
  const topupProxyInstance = await deployProxy(HardenedTopupProxy, [], { /*unsafeAllowLinkedLibraries: true,*/ /*unsafeAllowCustomTypes: true,*/ from: founderaddr });
  console.log('HardenedTopupProxy deployed at address: ', topupProxyInstance.address);
};
