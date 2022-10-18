// load dependencies
const { expect } = require('chai');
const truffleAssert = require('truffle-assertions');
const { deployProxy } = require('@openzeppelin/truffle-upgrades');
const { time } = require('@openzeppelin/test-helpers');

const web3utils = require('web3-utils');

// mockup contracts for tests
const MockUSDC = artifacts.require('ERC20USDCMock');
const MockDAI = artifacts.require('ERC20DAIMock');
const MockSwap = artifacts.require('TokenSwapExecutorMock');
const MockBridge = artifacts.require('TokenBridgeMock');

// production contracts
const HardenedTopupProxy = artifacts.require('HardenedTopupProxy');
const ExchangeProxy = artifacts.require('ExchangeProxy');
const ContractTrustedRegistry = artifacts.require('ContractWhitelist');

// packages for signing (non-prefixed) operations
const bip39 = require('bip39');
const { hdkey } = require('ethereumjs-wallet');
const secp256k1 = require('secp256k1');


contract('HardenedTopupProxy: Trusted signature flow', function (accounts) {
  beforeEach(async function () {
    // 1. deploy mocked token, swap aggregator and bridge
    this.mockusdc = await MockUSDC.new(accounts[0], { from: accounts[0] });
    this.mockdai = await MockDAI.new(accounts[0], { from: accounts[0] });
    this.swapmock = await MockSwap.new({ from: accounts[0] });
    this.bridgemock = await MockBridge.new({ from: accounts[0] });
    
    // 2. deploy topup proxy (setup chain id to develop) and exchnge proxy
    this.topupproxy = await deployProxy(HardenedTopupProxy, [web3.utils.toBN('1337'), '0x820539'], { from: accounts[0] });
    this.exchangeproxy = await ExchangeProxy.new({ from: accounts[0] });

    // 3. initialize trusted contract registry
    this.registry = await deployProxy(ContractTrustedRegistry, { from: accounts[0] });
    await this.registry.add(this.bridgemock.address, { from: accounts[0] });

    // 4. connect contracts
    await this.topupproxy.setExchangeProxy(this.exchangeproxy.address, { from: accounts[0] });
    await this.exchangeproxy.setTransferProxy(this.topupproxy.address, { from: accounts[0] });
    await this.topupproxy.setTrustedRegistry(this.registry.address, { from: accounts[0] });
    await this.exchangeproxy.setTrustedRegistry(this.registry.address, { from: accounts[0] });
    await this.topupproxy.setCardPartnerAddress(accounts[8], { from: accounts[0] });
    await this.topupproxy.setCardTopupToken(this.mockusdc.address, { from: accounts[0] });
  });

  it('must allow topup using signed approval verify message', async function() {
    // 1. create EOA and provide role of 'trusted executor' to it
    const seed = await bip39.mnemonicToSeed("trophy just rib bamboo skirt follow such margin agree fence peanut vague");
    const hdk = hdkey.fromMasterSeed(seed);
    const addr_node = hdk.derivePath("m/44'/60'/0'/0/1"); //m/44'/60'/0'/0/0 is derivation path for the first account. m/44'/60'/0'/0/1 is the derivation path for the second account and so on
    const addr = addr_node.getWallet().getAddressString(); //check that this is the same with the address that ganache list for the first account to make sure the derivation is correct
    const private_key = addr_node.getWallet().getPrivateKey();
    //console.log("Account address=" + addr + ", private_key=" + web3.utils.bytesToHex(private_key));

    await this.topupproxy.grantRole(web3.utils.sha3("TRUSTED_EXECUTION"), addr, { from: accounts[0] });
    await this.topupproxy.setAllowanceSignatureTimespan(600, { from: accounts[0] });

    // 2. accounts[2] is to make topup
    await this.mockusdc.transfer(accounts[2], web3.utils.toBN('5000'), { from: accounts[0] });
    this.approveTx = await this.mockusdc.approve(this.topupproxy.address, web3.utils.toBN('5000'), { from: accounts[2] });

    // 3. sign the message by trusted executor (without prefix)
    const timestampApprove = await time.latest();
    const message = web3utils.encodePacked(
      {value: 'MOVER TOPUP ', type: 'string'},
      {value: web3.utils.keccak256(accounts[2]), type: 'bytes32'},
      {value: ' TOKEN ', type: 'string'},
      {value: this.mockusdc.address, type: 'address'},
      {value: ' AMOUNT ', type: 'string'},
      {value: web3.utils.toBN('5000'), type: 'uint256'},
      {value: ' TS ', type: 'string'},
      {value: timestampApprove, type: 'uint256'}
    );

    const msghash = Uint8Array.from(web3.utils.hexToBytes(web3.utils.keccak256(message)));
    const sig = secp256k1.ecdsaSign(msghash, private_key);
    const signature = [].concat(Array.from(sig.signature), (sig.recid + 27));

    // 4. call topup from accounts[2] providing signed recent approval verification
    const bridgeData = [].concat(web3.utils.hexToBytes(this.bridgemock.address), 
      web3.utils.hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000000')); // bridge fee (not used in mock bridge)
    const tx = await this.topupproxy.CardTopupTrusted(this.mockusdc.address, 
      web3.utils.toBN('5000'),
      web3.utils.toBN(timestampApprove),
      web3.utils.bytesToHex(signature),
      web3.utils.toBN(0),
      [],
      web3.utils.toBN(1),
      bridgeData, 
      '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] });

    truffleAssert.eventEmitted(tx, 'CardTopup', (ev) => {
      return ev.account.toString() === accounts[2] &&
      ev.token.toString() === this.mockusdc.address &&
      ev.valueToken.toString() === '5000' &&
      ev.valueUSDC.toString() === '5000';
      });
    expect((await this.mockusdc.balanceOf(this.bridgemock.address)).toString()).to.equal('5000');
  });

  it('must not allow topup when contract operation is paused', async function() {
    // 1. create EOA and provide role of 'trusted executor' to it
    const seed = await bip39.mnemonicToSeed("trophy just rib bamboo skirt follow such margin agree fence peanut vague");
    const hdk = hdkey.fromMasterSeed(seed);
    const addr_node = hdk.derivePath("m/44'/60'/0'/0/1"); //m/44'/60'/0'/0/0 is derivation path for the first account. m/44'/60'/0'/0/1 is the derivation path for the second account and so on
    const addr = addr_node.getWallet().getAddressString(); //check that this is the same with the address that ganache list for the first account to make sure the derivation is correct
    const private_key = addr_node.getWallet().getPrivateKey();

    await this.topupproxy.grantRole(web3.utils.sha3("TRUSTED_EXECUTION"), addr, { from: accounts[0] });
    await this.topupproxy.setAllowanceSignatureTimespan(600, { from: accounts[0] });

    // 2. accounts[2] is to make topup
    await this.mockusdc.transfer(accounts[2], web3.utils.toBN('5000'), { from: accounts[0] });
    this.approveTx = await this.mockusdc.approve(this.topupproxy.address, web3.utils.toBN('5000'), { from: accounts[2] });

    // 3. sign the message by trusted executor (without prefix)
    const timestampApprove = await time.latest();
    const message = web3utils.encodePacked(
      {value: 'MOVER TOPUP ', type: 'string'},
      {value: web3.utils.keccak256(accounts[2]), type: 'bytes32'},
      {value: ' TOKEN ', type: 'string'},
      {value: this.mockusdc.address, type: 'address'},
      {value: ' AMOUNT ', type: 'string'},
      {value: web3.utils.toBN('5000'), type: 'uint256'},
      {value: ' TS ', type: 'string'},
      {value: timestampApprove, type: 'uint256'}
    );

    const msghash = Uint8Array.from(web3.utils.hexToBytes(web3.utils.keccak256(message)));
    const sig = secp256k1.ecdsaSign(msghash, private_key);
    const signature = [].concat(Array.from(sig.signature), (sig.recid + 27));

    // pause contract operation
    await this.topupproxy.setPaused(true, { from: accounts[0] });

    // 4. call topup from accounts[2] providing signed recent approval verification
    const bridgeData = [].concat(web3.utils.hexToBytes(this.bridgemock.address), 
      web3.utils.hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000000'));

    await truffleAssert.reverts(this.topupproxy.CardTopupTrusted(this.mockusdc.address, 
      web3.utils.toBN('5000'),
      web3.utils.toBN(timestampApprove),
      web3.utils.bytesToHex(signature),
      web3.utils.toBN(0),
      [],
      web3.utils.toBN(1),
      bridgeData, 
      '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] }), 
    "operations paused");
  });

  it('must not allow topup when invalid signed approval verify message', async function() {
    // 1. create EOA and provide role of 'trusted executor' to it
    const seed = await bip39.mnemonicToSeed("trophy just rib bamboo skirt follow such margin agree fence peanut vague");
    const hdk = hdkey.fromMasterSeed(seed);
    const addr_node = hdk.derivePath("m/44'/60'/0'/0/1"); //m/44'/60'/0'/0/0 is derivation path for the first account. m/44'/60'/0'/0/1 is the derivation path for the second account and so on
    const addr = addr_node.getWallet().getAddressString(); //check that this is the same with the address that ganache list for the first account to make sure the derivation is correct
    const private_key = addr_node.getWallet().getPrivateKey();
    //console.log("Account address=" + addr + ", private_key=" + web3.utils.bytesToHex(private_key));

    await this.topupproxy.grantRole(web3.utils.sha3("TRUSTED_EXECUTION"), addr, { from: accounts[0] });
    await this.topupproxy.setAllowanceSignatureTimespan(600, { from: accounts[0] });

    // 2. accounts[2] is to make topup
    await this.mockusdc.transfer(accounts[2], web3.utils.toBN('5000'), { from: accounts[0] });
    this.approveTx = await this.mockusdc.approve(this.topupproxy.address, web3.utils.toBN('5000'), { from: accounts[2] });

    // 3. sign the message by trusted executor (without prefix)
    // this signature has wrong amount
    const timestampApprove = await time.latest();
    const message = web3utils.encodePacked(
      {value: 'MOVER TOPUP ', type: 'string'},
      {value: web3.utils.keccak256(accounts[2]), type: 'bytes32'},
      {value: ' TOKEN ', type: 'string'},
      {value: this.mockusdc.address, type: 'address'},
      {value: ' AMOUNT ', type: 'string'},
      {value: web3.utils.toBN('1230000'), type: 'uint256'},
      {value: ' TS ', type: 'string'},
      {value: timestampApprove, type: 'uint256'}
    );

    const msghash = Uint8Array.from(web3.utils.hexToBytes(web3.utils.keccak256(message))); //Buffer.from(web3.utils.keccak256(message), 'hex'); //web3.utils.hexToBytes(web3.utils.keccak256(message));
    const sig = secp256k1.ecdsaSign(msghash, private_key);
    const signature = [].concat(Array.from(sig.signature), (sig.recid + 27));

    const bridgeData = [].concat(web3.utils.hexToBytes(this.bridgemock.address), 
      web3.utils.hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000000')); // bridge fee (not used in mock bridge)

    await truffleAssert.reverts(this.topupproxy.CardTopupTrusted(this.mockusdc.address, 
          web3.utils.toBN('5000'),
          web3.utils.toBN(timestampApprove),
          web3.utils.bytesToHex(signature),
          web3.utils.toBN(0),
          [],
          web3.utils.toBN(1),
          bridgeData, 
          '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] }), 
        "wrong signature");

    // this signature has wrong account
    const message2 = web3utils.encodePacked(
      {value: 'MOVER TOPUP ', type: 'string'},
      {value: web3.utils.keccak256(accounts[5]), type: 'bytes32'},
      {value: ' TOKEN ', type: 'string'},
      {value: this.mockusdc.address, type: 'address'},
      {value: ' AMOUNT ', type: 'string'},
      {value: web3.utils.toBN('5000'), type: 'uint256'},
      {value: ' TS ', type: 'string'},
      {value: timestampApprove, type: 'uint256'}
    );

    const msghash2 = Uint8Array.from(web3.utils.hexToBytes(web3.utils.keccak256(message2)));
    const sig2 = secp256k1.ecdsaSign(msghash2, private_key);
    const signature2 = [].concat(Array.from(sig2.signature), (sig2.recid + 27));

    await truffleAssert.reverts(this.topupproxy.CardTopupTrusted(this.mockusdc.address, 
      web3.utils.toBN('5000'),
      web3.utils.toBN(timestampApprove),
      web3.utils.bytesToHex(signature2),
      web3.utils.toBN(0),
      [],
      web3.utils.toBN(1),
      bridgeData, 
      '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] }), 
    "wrong signature");

    // this is valid signature, but from wrong signer
    const message3 = web3utils.encodePacked(
      {value: 'MOVER TOPUP ', type: 'string'},
      {value: web3.utils.keccak256(accounts[2]), type: 'bytes32'},
      {value: ' TOKEN ', type: 'string'},
      {value: this.mockusdc.address, type: 'address'},
      {value: ' AMOUNT ', type: 'string'},
      {value: web3.utils.toBN('5000'), type: 'uint256'},
      {value: ' TS ', type: 'string'},
      {value: timestampApprove, type: 'uint256'}
    );

    const msghash3 = Uint8Array.from(web3.utils.hexToBytes(web3.utils.keccak256(message3)));

    const addr_node2 = hdk.derivePath("m/44'/60'/0'/0/5"); //m/44'/60'/0'/0/0 is derivation path for the first account. m/44'/60'/0'/0/1 is the derivation path for the second account and so on
    const private_key2 = addr_node2.getWallet().getPrivateKey();

    const sig3 = secp256k1.ecdsaSign(msghash3, private_key2);
    const signature3 = [].concat(Array.from(sig3.signature), (sig3.recid + 27));

    await truffleAssert.reverts(this.topupproxy.CardTopupTrusted(this.mockusdc.address, 
      web3.utils.toBN('5000'),
      web3.utils.toBN(timestampApprove),
      web3.utils.bytesToHex(signature3),
      web3.utils.toBN(0),
      [],
      web3.utils.toBN(1),
      bridgeData, 
      '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] }), 
    "wrong signature");

    // this signature timestamp is too old
    const message4 = web3utils.encodePacked(
      {value: 'MOVER TOPUP ', type: 'string'},
      {value: web3.utils.keccak256(accounts[2]), type: 'bytes32'},
      {value: ' TOKEN ', type: 'string'},
      {value: this.mockusdc.address, type: 'address'},
      {value: ' AMOUNT ', type: 'string'},
      {value: web3.utils.toBN('5000'), type: 'uint256'},
      {value: ' TS ', type: 'string'},
      {value: 123000000, type: 'uint256'}
    );

    const msghash4 = Uint8Array.from(web3.utils.hexToBytes(web3.utils.keccak256(message4)));
    const sig4 = secp256k1.ecdsaSign(msghash4, private_key);
    const signature4 = [].concat(Array.from(sig4.signature), (sig4.recid + 27));

    await truffleAssert.reverts(this.topupproxy.CardTopupTrusted(this.mockusdc.address, 
      web3.utils.toBN('5000'),
      web3.utils.toBN(123000000),
      web3.utils.bytesToHex(signature4),
      web3.utils.toBN(0),
      [],
      web3.utils.toBN(1),
      bridgeData, 
      '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] }), 
    "old sig");
  });

  it('must allow topup with fee using signed approval verify message', async function() {
    // 1. create EOA and provide role of 'trusted executor' to it
    const seed = await bip39.mnemonicToSeed("trophy just rib bamboo skirt follow such margin agree fence peanut vague");
    const hdk = hdkey.fromMasterSeed(seed);
    const addr_node = hdk.derivePath("m/44'/60'/0'/0/1"); //m/44'/60'/0'/0/0 is derivation path for the first account. m/44'/60'/0'/0/1 is the derivation path for the second account and so on
    const addr = addr_node.getWallet().getAddressString(); //check that this is the same with the address that ganache list for the first account to make sure the derivation is correct
    const private_key = addr_node.getWallet().getPrivateKey();
    //console.log("Account address=" + addr + ", private_key=" + web3.utils.bytesToHex(private_key));

    await this.topupproxy.grantRole(web3.utils.sha3("TRUSTED_EXECUTION"), addr, { from: accounts[0] });
    await this.topupproxy.setAllowanceSignatureTimespan(600, { from: accounts[0] });

    // set topup fee (10%)
    await this.topupproxy.setTopupFee(web3.utils.toBN('100000000000000000'), { from: accounts[0] });

    // 2. accounts[2] is to make topup
    await this.mockusdc.transfer(accounts[2], web3.utils.toBN('5000'), { from: accounts[0] });
    this.approveTx = await this.mockusdc.approve(this.topupproxy.address, web3.utils.toBN('5000'), { from: accounts[2] });

    // 3. sign the message by trusted executor (without prefix)
    const timestampApprove = await time.latest();
    const message = web3utils.encodePacked(
      {value: 'MOVER TOPUP ', type: 'string'},
      {value: web3.utils.keccak256(accounts[2]), type: 'bytes32'},
      {value: ' TOKEN ', type: 'string'},
      {value: this.mockusdc.address, type: 'address'},
      {value: ' AMOUNT ', type: 'string'},
      {value: web3.utils.toBN('5000'), type: 'uint256'},
      {value: ' TS ', type: 'string'},
      {value: timestampApprove, type: 'uint256'}
    );

    const msghash = Uint8Array.from(web3.utils.hexToBytes(web3.utils.keccak256(message)));
    const sig = secp256k1.ecdsaSign(msghash, private_key);
    const signature = [].concat(Array.from(sig.signature), (sig.recid + 27));

    // 4. call topup from accounts[2] providing signed recent approval verification
    const bridgeData = [].concat(web3.utils.hexToBytes(this.bridgemock.address), 
      web3.utils.hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000000')); // bridge fee (not used in mock bridge)
    const tx = await this.topupproxy.CardTopupTrusted(this.mockusdc.address, 
      web3.utils.toBN('5000'),
      web3.utils.toBN(timestampApprove),
      web3.utils.bytesToHex(signature),
      web3.utils.toBN(0),
      [],
      web3.utils.toBN(1),
      bridgeData, 
      '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] });

    truffleAssert.eventEmitted(tx, 'CardTopup', (ev) => {
      return ev.account.toString() === accounts[2] &&
      ev.token.toString() === this.mockusdc.address &&
      ev.valueToken.toString() === '5000' &&
      ev.valueUSDC.toString() === '4500';
      });
    expect((await this.mockusdc.balanceOf(this.bridgemock.address)).toString()).to.equal('4500');
  });

  it('must allow topup with swap using signed approval verify message', async function() {
    // 1. create EOA and provide role of 'trusted executor' to it
    const seed = await bip39.mnemonicToSeed("trophy just rib bamboo skirt follow such margin agree fence peanut vague");
    const hdk = hdkey.fromMasterSeed(seed);
    const addr_node = hdk.derivePath("m/44'/60'/0'/0/1"); //m/44'/60'/0'/0/0 is derivation path for the first account. m/44'/60'/0'/0/1 is the derivation path for the second account and so on
    const addr = addr_node.getWallet().getAddressString(); //check that this is the same with the address that ganache list for the first account to make sure the derivation is correct
    const private_key = addr_node.getWallet().getPrivateKey();
    //console.log("Account address=" + addr + ", private_key=" + web3.utils.bytesToHex(private_key));

    await this.topupproxy.grantRole(web3.utils.sha3("TRUSTED_EXECUTION"), addr, { from: accounts[0] });
    await this.topupproxy.setAllowanceSignatureTimespan(600, { from: accounts[0] });

    // 2. accounts[2] is to make topup
    await this.mockdai.transfer(accounts[2], web3.utils.toBN('1000000000000000000'), { from: accounts[0] });

    // 3. sign the message by trusted executor (without prefix)
    const timestampApprove = await time.latest();
    const message = web3utils.encodePacked(
      {value: 'MOVER TOPUP ', type: 'string'},
      {value: web3.utils.keccak256(accounts[2]), type: 'bytes32'},
      {value: ' TOKEN ', type: 'string'},
      {value: this.mockdai.address, type: 'address'},
      {value: ' AMOUNT ', type: 'string'},
      {value: web3.utils.toBN('1000000000000000000'), type: 'uint256'},
      {value: ' TS ', type: 'string'},
      {value: timestampApprove, type: 'uint256'}
    );

    const msghash = Uint8Array.from(web3.utils.hexToBytes(web3.utils.keccak256(message)));
    const sig = secp256k1.ecdsaSign(msghash, private_key);
    const signature = [].concat(Array.from(sig.signature), (sig.recid + 27));

    // transfer all USDC mock balance to swap executor
    await this.mockusdc.transfer(this.swapmock.address, web3.utils.toBN('1000000000000'), { from: accounts[0] });
    expect((await this.mockusdc.balanceOf(accounts[0])).toString()).to.equal('0');

    await this.registry.add(this.swapmock.address, { from: accounts[0] });

    await this.mockdai.transfer(accounts[2], web3.utils.toBN('1000000000000000000'), { from: accounts[0] });
    this.approveTx = await this.mockdai.approve(this.topupproxy.address, web3.utils.toBN('1000000000000000000'), { from: accounts[2] });

    const swapData = [].concat(web3.utils.hexToBytes(this.swapmock.address), web3.utils.hexToBytes(this.swapmock.address), 
    web3.utils.hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000000'), 
    web3.utils.hexToBytes('0xec6cc0cc000000000000000000000000'), //func hash + padding for address of token from
    web3.utils.hexToBytes(this.mockdai.address),
    web3.utils.hexToBytes('0x000000000000000000000000'), //padding for address of token to
    web3.utils.hexToBytes(this.mockusdc.address),
    web3.utils.hexToBytes('0x0000000000000000000000000000000000000000000000000DE0B6B3A7640000'));


    // 4. call topup from accounts[2] providing signed recent approval verification
    const bridgeData = [].concat(web3.utils.hexToBytes(this.bridgemock.address), 
      web3.utils.hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000000')); // bridge fee (not used in mock bridge)
    const tx = await this.topupproxy.CardTopupTrusted(this.mockdai.address, 
      web3.utils.toBN('1000000000000000000'),
      web3.utils.toBN(timestampApprove),
      web3.utils.bytesToHex(signature),
      web3.utils.toBN(0),
      swapData,
      web3.utils.toBN(1),
      bridgeData, 
      '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] });

    truffleAssert.eventEmitted(tx, 'CardTopup', (ev) => {
      return ev.account.toString() === accounts[2] &&
      ev.token.toString() === this.mockdai.address &&
      ev.valueToken.toString() === '1000000000000000000' &&
      ev.valueUSDC.toString() === '900000';
      });

    const innerTx = await truffleAssert.createTransactionResult(this.exchangeproxy, tx.tx);
    truffleAssert.eventEmitted(innerTx, 'ExecuteSwap', (ev) => {
      return ev.user.toString() === this.topupproxy.address &&
      ev.tokenIn.toString() === this.mockdai.address &&
      ev.tokenOut.toString() === this.mockusdc.address &&
      ev.amountIn.toString() === '1000000000000000000' &&
      ev.amountOut.toString() === '900000';
      });
  
    // expect balance of 'bridge' to have usdc
    expect((await this.mockusdc.balanceOf(this.bridgemock.address)).toString()).to.equal('900000');
  });
});
