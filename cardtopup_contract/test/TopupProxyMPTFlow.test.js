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

// MPT proof generator (JS implementation for develop chainID)
const { ProofGenerator } = require('./utils/generator.js');

contract('HardenedTopupProxy: MPT proof verification', function (accounts) {
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

  it('must allow topup using provided MPT proof', async function() {
    // 1. transfer funds and create approve transaction
    await this.mockusdc.transfer(accounts[2], web3.utils.toBN('8000'), { from: accounts[0] });
    expect((await this.mockusdc.balanceOf(accounts[2])).toString()).to.equal('8000');
    this.approveTx = await this.mockusdc.approve(this.topupproxy.address, web3.utils.toBN('8000'), { from: accounts[2] });
    await time.advanceBlock();
    //console.log("Test tx: ", this.approveTx);
    //console.log("Transaction block number=" + this.approveTx.receipt.blockNumber + ", index(position)=" + this.approveTx.receipt.transactionIndex);

    // 2. generate proof using block number and index of transaction in the block
    let generator = new ProofGenerator();
    let proof = await generator.calcTransactionProof(this.approveTx.receipt.blockNumber, this.approveTx.receipt.transactionIndex);
    //console.log("Proof: ", web3.utils.bytesToHex(Array.from(proof)));

    // 3. prepare and call topup providing proof for on-chain verification of recent approval
    const bridgeData = [].concat(web3.utils.hexToBytes(this.bridgemock.address), 
      web3.utils.hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000000')); // bridge fee (not used in mock bridge)
    const tx = await this.topupproxy.CardTopupMPTProof(this.mockusdc.address, 
      web3.utils.toBN('8000'),
      web3.utils.toBN(this.approveTx.receipt.blockNumber),
      web3.utils.bytesToHex(Array.from(proof)),
      web3.utils.toBN(0),
      [],
      web3.utils.toBN(1),
      bridgeData, 
      '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] });
  });

  it('must not allow topup when provided MPT proof is incorrect', async function() {
    // 1. transfer funds and create approve transaction
    await this.mockusdc.transfer(accounts[2], web3.utils.toBN('8000'), { from: accounts[0] });
    expect((await this.mockusdc.balanceOf(accounts[2])).toString()).to.equal('8000');

    // 2. generate proof using block number and index of transaction in the block
    let generator = new ProofGenerator();
    const bridgeData = [].concat(web3.utils.hexToBytes(this.bridgemock.address), 
      web3.utils.hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000000')); // bridge fee (not used in mock bridge)

    // 3. this approve is from different sender
    this.approveTx = await this.mockusdc.approve(this.topupproxy.address, web3.utils.toBN('8000'), { from: accounts[3] });
    await time.advanceBlock();
    let proof = await generator.calcTransactionProof(this.approveTx.receipt.blockNumber, this.approveTx.receipt.transactionIndex);

    await truffleAssert.reverts(this.topupproxy.CardTopupMPTProof(this.mockusdc.address, 
      web3.utils.toBN('8000'),
      web3.utils.toBN(this.approveTx.receipt.blockNumber),
      web3.utils.bytesToHex(Array.from(proof)),
      web3.utils.toBN(0),
      [],
      web3.utils.toBN(1),
      bridgeData, 
      '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] }),
    "sender mismatch");

    // 4. this is not approve tx
    this.approveTx2 = await this.mockusdc.transfer(accounts[3], web3.utils.toBN('1000'), { from: accounts[2] });
    await time.advanceBlock();
    let proof2 = await generator.calcTransactionProof(this.approveTx2.receipt.blockNumber, this.approveTx2.receipt.transactionIndex);

    await truffleAssert.reverts(this.topupproxy.CardTopupMPTProof(this.mockusdc.address, 
      web3.utils.toBN('8000'),
      web3.utils.toBN(this.approveTx2.receipt.blockNumber),
      web3.utils.bytesToHex(Array.from(proof2)),
      web3.utils.toBN(0),
      [],
      web3.utils.toBN(1),
      bridgeData, 
      '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] }),
    "method mismatch");

    // 5. this approve is for different spender
    this.approveTx3 = await this.mockusdc.approve(accounts[5], web3.utils.toBN('8000'), { from: accounts[3] });
    await time.advanceBlock();
    let proof3 = await generator.calcTransactionProof(this.approveTx3.receipt.blockNumber, this.approveTx3.receipt.transactionIndex);

    await truffleAssert.reverts(this.topupproxy.CardTopupMPTProof(this.mockusdc.address, 
      web3.utils.toBN('8000'),
      web3.utils.toBN(this.approveTx3.receipt.blockNumber),
      web3.utils.bytesToHex(Array.from(proof3)),
      web3.utils.toBN(0),
      [],
      web3.utils.toBN(1),
      bridgeData, 
      '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] }),
    "sender mismatch");
  });

  it('must not allow topup when curent allowance value is too high or too low', async function() {
    // 1. transfer funds and create approve transaction
    await this.mockusdc.transfer(accounts[2], web3.utils.toBN('8000'), { from: accounts[0] });
    expect((await this.mockusdc.balanceOf(accounts[2])).toString()).to.equal('8000');
    this.approveTx = await this.mockusdc.approve(this.topupproxy.address, web3.utils.toBN('8000'), { from: accounts[2] });
    await time.advanceBlock();
    //console.log("Test tx: ", this.approveTx);
    //console.log("Transaction block number=" + this.approveTx.receipt.blockNumber + ", index(position)=" + this.approveTx.receipt.transactionIndex);

    // 2. generate proof using block number and index of transaction in the block
    let generator = new ProofGenerator();
    let proof = await generator.calcTransactionProof(this.approveTx.receipt.blockNumber, this.approveTx.receipt.transactionIndex);
    //console.log("Proof: ", web3.utils.bytesToHex(Array.from(proof)));

    // 3. prepare and call topup providing proof for on-chain verification of recent approval
    const bridgeData = [].concat(web3.utils.hexToBytes(this.bridgemock.address), 
      web3.utils.hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000000')); // bridge fee (not used in mock bridge)

    await this.mockusdc.approve(this.topupproxy.address, web3.utils.toBN('50000'), { from: accounts[2] });

    await truffleAssert.reverts(this.topupproxy.CardTopupMPTProof(this.mockusdc.address, 
      web3.utils.toBN('8000'),
      web3.utils.toBN(this.approveTx.receipt.blockNumber),
      web3.utils.bytesToHex(Array.from(proof)),
      web3.utils.toBN(0),
      [],
      web3.utils.toBN(1),
      bridgeData, 
      '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] }),
    "excessive allowance");

    await this.mockusdc.approve(this.topupproxy.address, web3.utils.toBN('500'), { from: accounts[2] });

    await truffleAssert.reverts(this.topupproxy.CardTopupMPTProof(this.mockusdc.address, 
      web3.utils.toBN('8000'),
      web3.utils.toBN(this.approveTx.receipt.blockNumber),
      web3.utils.bytesToHex(Array.from(proof)),
      web3.utils.toBN(0),
      [],
      web3.utils.toBN(1),
      bridgeData, 
      '0x0000000000000000000000000000000000000000000000000000000000000000', { from: accounts[2] }),
    "insufficient allowance");
  });
});
