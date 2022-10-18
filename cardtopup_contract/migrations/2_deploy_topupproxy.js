const HardenedTopupProxy = artifacts.require('HardenedTopupProxy');

const { deployProxy } = require('@openzeppelin/truffle-upgrades');

module.exports = async function (deployer, network, accounts) {
  let founderaddr = "";
  let chainID;
  let chainIDRLP;
  if (network == "live" || network == "live-fork") {
  } else if (network == "ropsten" || network == "ropsten-fork" /* for dry-run */) {
  } else if (network == "kovan" || network == "kovan-fork" /* for dry-run */) {
  } else if (network == "polygon" || network == "polygon-fork" /* for dry-run */) {
    founderaddr = "";
    chainID = web3.utils.toBN('137');
    chainIDRLP = '0x8189';
  } else {
    founderaddr = accounts[0];
    chainID = web3.utils.toBN('1337');
    chainIDRLP = '0x820539';
  }

  if (founderaddr == '') {
    throw("ERROR: no address set for founder");
  }

  if (chainID == undefined) {
    throw("ERROR: no address set for chainID");
  }

  if (chainIDRLP == undefined) {
    throw("ERROR: no address set for chainIDRLP");
  }

  console.log("DEPLOYING HardenedTopupProxy, network=" + network);
  const topupProxyInstance = await deployProxy(HardenedTopupProxy, [chainID, chainIDRLP], { /*unsafeAllowLinkedLibraries: true,*/ /*unsafeAllowCustomTypes: true,*/ from: founderaddr });
  console.log('HardenedTopupProxy deployed at address: ', topupProxyInstance.address);
};
