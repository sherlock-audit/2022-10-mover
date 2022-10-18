// load dependencies
const { expect } = require('chai');
const truffleAssert = require('truffle-assertions');
const { deployProxy } = require('@openzeppelin/truffle-upgrades');
const { time } = require('@openzeppelin/test-helpers');

// mockup contracts for tests
const MockUSDC = artifacts.require('ERC20USDCMock');
const MockSwap = artifacts.require('TokenSwapExecutorMock');
const MockBridge = artifacts.require('TokenBridgeMock');

// production contracts
const HardenedTopupProxy = artifacts.require('HardenedTopupProxy');
const ExchangeProxy = artifacts.require('ExchangeProxy');
const ContractTrustedRegistry = artifacts.require('ContractWhitelist');

// permit supporting packages
const bip39 = require('bip39');
const { hdkey } = require('ethereumjs-wallet');
const { Eip2612PermitUtils, PrivateKeyProviderConnector } = require('@1inch/permit-signed-approvals-utils');

const truffleSeed = "foil pluck wide begin exchange pottery embark bean eager skin shaft fiber";

contract('HardenedTopupProxy: Permit flow', function (accounts) {
  beforeEach(async function () {
    // 1. deploy mocked token, swap aggregator and bridge
    this.mockusdc = await MockUSDC.new(accounts[0], { from: accounts[0] });
    this.swapmock = await MockSwap.new({ from: accounts[0] });
    this.bridgemock = await MockBridge.new({ from: accounts[0] });

    // 2. deploy topup proxy (setup chain id to develop) and exchnge proxy
    this.topupproxy = await deployProxy(HardenedTopupProxy, [web3.utils.toBN('1337'), '0x820539'], { from: accounts[0] });
    this.exchangeproxy = await ExchangeProxy.new({ from: accounts[0] });

    // 3. initialize trusted contract registry
    this.registry = await deployProxy(ContractTrustedRegistry, { from: accounts[0] });
    await this.registry.add(this.swapmock.address, { from: accounts[0] });
    await this.registry.add(this.bridgemock.address, { from: accounts[0] });

    // 4. connect contracts
    await this.topupproxy.setExchangeProxy(this.swapmock.address, { from: accounts[0] });
    await this.exchangeproxy.setTransferProxy(this.topupproxy.address, { from: accounts[0] });
    await this.topupproxy.setTrustedRegistry(this.registry.address, { from: accounts[0] });
    await this.exchangeproxy.setTrustedRegistry(this.registry.address, { from: accounts[0] });
    await this.topupproxy.setCardPartnerAddress(accounts[8], { from: accounts[0] });
    await this.topupproxy.setCardTopupToken(this.mockusdc.address, { from: accounts[0] });
  });

  it('must allow topup using EIP-2612 Permit()', async function() {
    // 1. create address matching accounts[2] (to get private key for signing) and sign permit
    const futureTimestamp = 2686021120 // some random ts in far future for deadline
    const amountTopup = web3.utils.toBN('11000');

    const seed = await bip39.mnemonicToSeed(truffleSeed);
    const hdk = hdkey.fromMasterSeed(seed);
    const addr_node = hdk.derivePath("m/44'/60'/0'/0/2"); //m/44'/60'/0'/0/0 is derivation path for the first account. m/44'/60'/0'/0/1 is the derivation path for the second account and so on
    const addr = addr_node.getWallet().getAddressString(); //check that this is the same with the address that ganache list for the first account to make sure the derivation is correct
    const private_key = addr_node.getWallet().getPrivateKey();
    //console.log("Account address=" + addr + ", private_key=" + web3.utils.bytesToHex(private_key));

    const connector = new PrivateKeyProviderConnector(private_key, web3);
    const eip2612PermitUtils = new Eip2612PermitUtils(connector);
  
    const tokenNonce = await eip2612PermitUtils.getTokenNonce(
        this.mockusdc.address,
        accounts[2]
    );

    const permitParams = {
      owner: accounts[2],
      spender: this.topupproxy.address,
      value: amountTopup,
      nonce: tokenNonce,
      deadline: futureTimestamp
    };

    const signature = await eip2612PermitUtils.buildPermitSignature(
      {
          ...permitParams,
          nonce: tokenNonce,
      },
      await web3.eth.getChainId(),
      "USDCMock",
      this.mockusdc.address
    );
  
    const v = web3.utils.hexToBytes(signature)[64];
    const r = web3.utils.hexToBytes(signature).slice(0,32);
    const s = web3.utils.hexToBytes(signature).slice(32,64);

    //console.log('Permit signature', signature);
    //console.log("v: ", v);
    //console.log("r: ", r);
    //console.log("s: ", s);  

    // 2. transfer funds to accounts[2] for topup
    await this.mockusdc.transfer(accounts[2], web3.utils.toBN(amountTopup), { from: accounts[0] });
    expect((await this.mockusdc.balanceOf(accounts[2])).toString()).to.equal(amountTopup.toString());

    // 3. pack permit data into bytes[32*7] and call topup
    //address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s
    const permitData = [].concat(web3.utils.hexToBytes(web3.utils.padLeft(accounts[2], 64)),
      web3.utils.hexToBytes(web3.utils.padLeft(this.topupproxy.address, 64)),
      web3.utils.hexToBytes(web3.utils.padLeft(web3.utils.toHex(web3.utils.toBN(amountTopup)), 64)),
      web3.utils.hexToBytes(web3.utils.padLeft(web3.utils.toHex(web3.utils.toBN(futureTimestamp)), 64)),
      web3.utils.hexToBytes(web3.utils.padLeft(web3.utils.toHex(v), 64)),
      r,
      s
    );

    const bridgeData = [].concat(web3.utils.hexToBytes(this.bridgemock.address), 
      web3.utils.hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000000')); // bridge fee (not used in mock bridge)
    const tx = await this.topupproxy.CardTopupPermit(this.mockusdc.address, 
      web3.utils.toBN(amountTopup),
      web3.utils.bytesToHex(permitData),
      web3.utils.toBN(0),
      [],
      web3.utils.toBN(1),
      bridgeData, 
      '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] });
  });


  it('must allow topup EIP-2612 Permit() and reset allowance', async function() {
    // 1. create address matching accounts[2] (to get private key for signing) and sign permit
    const futureTimestamp = 2686021120 // some random ts in far future for deadline
    const amountTopup = web3.utils.toBN('11000');

    const seed = await bip39.mnemonicToSeed(truffleSeed);
    const hdk = hdkey.fromMasterSeed(seed);
    const addr_node = hdk.derivePath("m/44'/60'/0'/0/2"); //m/44'/60'/0'/0/0 is derivation path for the first account. m/44'/60'/0'/0/1 is the derivation path for the second account and so on
    const private_key = addr_node.getWallet().getPrivateKey();

    const connector = new PrivateKeyProviderConnector(private_key, web3);
    const eip2612PermitUtils = new Eip2612PermitUtils(connector);
  
    const tokenNonce = await eip2612PermitUtils.getTokenNonce(
      this.mockusdc.address,
      accounts[2]
    );

    const permitParams = {
        owner: accounts[2],
        spender: this.topupproxy.address,
        value: web3.utils.toBN('11000'),
        nonce: tokenNonce,
        deadline: futureTimestamp
    };
    
    const signature = await eip2612PermitUtils.buildPermitSignature(
      {
          ...permitParams,
          nonce: tokenNonce,
      },
      await web3.eth.getChainId(),
      "USDCMock",
      this.mockusdc.address
    );
  
    const v = web3.utils.hexToBytes(signature)[64];
    const r = web3.utils.hexToBytes(signature).slice(0,32);
    const s = web3.utils.hexToBytes(signature).slice(32,64);

    // 2. transfer funds to accounts[2] for topup
    await this.mockusdc.transfer(accounts[2], web3.utils.toBN(amountTopup), { from: accounts[0] });
    expect((await this.mockusdc.balanceOf(accounts[2])).toString()).to.equal(amountTopup.toString());

    // 3. pack permit data into bytes[32*7] and call topup
    //address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s
    const permitData = [].concat(web3.utils.hexToBytes(web3.utils.padLeft(accounts[2], 64)),
      web3.utils.hexToBytes(web3.utils.padLeft(this.topupproxy.address, 64)),
      web3.utils.hexToBytes(web3.utils.padLeft(web3.utils.toHex(web3.utils.toBN(amountTopup)), 64)),
      web3.utils.hexToBytes(web3.utils.padLeft(web3.utils.toHex(web3.utils.toBN(futureTimestamp)), 64)),
      web3.utils.hexToBytes(web3.utils.padLeft(web3.utils.toHex(v), 64)),
      r,
      s
    );
    amountTopup
    await this.mockusdc.approve(this.topupproxy.address, web3.utils.toBN('500000'), { from: accounts[2] });

    const bridgeData = [].concat(web3.utils.hexToBytes(this.bridgemock.address), 
      web3.utils.hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000000'));
    const tx = await this.topupproxy.CardTopupPermit(this.mockusdc.address, 
      web3.utils.toBN(amountTopup),
      web3.utils.bytesToHex(permitData),
      web3.utils.toBN(0),
      [],
      web3.utils.toBN(1),
      bridgeData, 
      '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] });
    expect((await this.mockusdc.balanceOf(this.bridgemock.address)).toString()).to.equal('11000');
  });
});
