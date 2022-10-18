const HardenedTopupProxy = artifacts.require('HardenedTopupProxy');
const ExchangeProxy = artifacts.require('ExchangeProxy');
const TrustedRegistry = artifacts.require('ContractWhitelist');

const { deployProxy, upgradeProxy } = require('@openzeppelin/truffle-upgrades');

module.exports = async function (deployer, network, accounts) {
  let founderaddr = "";
  let topupproxy = "";
  let exchangeproxy = "";
  let trustedregistry = "";

  let cardpartneraddr = "";
  let cardtokenaddr = "";

  if (network == "live" || network == "live-fork") {
  } else if (network == "ropsten" || network == "ropsten-fork" /* for dry-run */) {
  } else if (network == "kovan" || network == "kovan-fork" /* for dry-run */) {
  } else if (network == "polygon" || network == "polygon-fork" /* for dry-run */) {
    founderaddr = "";
    topupproxy = await HardenedTopupProxy.deployed();
    exchangeproxy = await ExchangeProxy.deployed();
    trustedregistry = await TrustedRegistry.deployed();
    cardpartneraddr = "0xd5b15d08ab7f2293c25dd93b833afbe7958b0140";
    cardtokenaddr = "0x2791bca1f2de4661ed88a30c99a7a9449aa84174";
  } else {
    founderaddr = accounts[0];
    topupproxy = await HardenedTopupProxy.deployed();
    exchangeproxy = await ExchangeProxy.deployed();
    trustedregistry = await TrustedRegistry.deployed();
    cardpartneraddr = "0xd5b15d08ab7f2293c25dd93b833afbe7958b0140";
    cardtokenaddr = "0x2791bca1f2de4661ed88a30c99a7a9449aa84174";
  }

  if (founderaddr == '') {
    throw("ERROR: no address set for founder");
  }
  if (topupproxy == undefined || topupproxy.address == undefined) {
    throw("ERROR: topup proxy deployment is not detected");
  }
  if (exchangeproxy == undefined || exchangeproxy.address == undefined) {
    throw("ERROR: exchange proxy deployment is not detected");
  }
  if (trustedregistry == undefined || trustedregistry.address == undefined) {
    throw("ERROR: trustedregistry deployment is not detected");
  }
  if (cardpartneraddr == '') {
    throw("ERROR: no address set for card partner address");
  }
  if (cardtokenaddr == '') {
    throw("ERROR: no address set for card token address");
  }

  // connect contracts
  await topupproxy.setExchangeProxy.sendTransaction(exchangeproxy.address, { from: founderaddr });
  console.log('Connected Exchange proxy at ' + exchangeproxy.address + ' to Topup proxy at ' + topupproxy.address);
  await exchangeproxy.setTransferProxy.sendTransaction(topupproxy.address, { from: founderaddr });
  console.log('Connected Topup proxy at ' + topupproxy.address + ' to Exchange proxy at ' + exchangeproxy.address);
  await topupproxy.setTrustedRegistry.sendTransaction(trustedregistry.address, { from: founderaddr });
  console.log('Connected Trusted registry at ' + trustedregistry.address + ' to Topup proxy at ' + topupproxy.address);
  await exchangeproxy.setTrustedRegistry.sendTransaction(trustedregistry.address, { from: founderaddr });
  console.log('Connected Trusted registry at ' + trustedregistry.address + ' to Exchange proxy at ' + exchangeproxy.address);

  // set card topup token
  await topupproxy.setCardPartnerAddress.sendTransaction(cardpartneraddr, { from: founderaddr });
  console.log('Set card parnter address on L1 to ' + cardpartneraddr);
  await topupproxy.setCardTopupToken.sendTransaction(cardtokenaddr, { from: founderaddr });
  console.log('Set card topup token address on network ' + network + ' to ' + exchangeproxy.address);
};
