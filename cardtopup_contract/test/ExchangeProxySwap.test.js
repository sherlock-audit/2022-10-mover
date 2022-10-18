// Load dependencies
const { expect } = require('chai');
const truffleAssert = require('truffle-assertions');
const { deployProxy } = require('@openzeppelin/truffle-upgrades');
const { time } = require('@openzeppelin/test-helpers');

const ExchangeProxy = artifacts.require('ExchangeProxy');
const MockDAI = artifacts.require('ERC20DAIMock');
const MockUSDC = artifacts.require('ERC20USDCMock');
const MockTokenSwapExecutor = artifacts.require('TokenSwapExecutorMock');
const ContractTrustedRegistry = artifacts.require('ContractWhitelist');

contract('Exchange proxy (token swap scenarios)', function (accounts) {
  beforeEach(async function () {
    this.exchangeproxy = await ExchangeProxy.new({ from: accounts[0] });

    this.mockdai = await MockDAI.new(accounts[0], { from: accounts[0] });
    this.mockusdc = await MockUSDC.new(accounts[0], { from: accounts[0] });

    this.mockexecutor = await MockTokenSwapExecutor.new({ from: accounts[0] });

    this.registry = await deployProxy(ContractTrustedRegistry, { from: accounts[0] });

    await this.exchangeproxy.setTrustedRegistry(this.registry.address, { from: accounts[0] });
    await this.registry.add(this.mockexecutor.address, { from: accounts[0] });

    await time.advanceBlock();
  });

  it('should execute swap producing exchange of tokens (no fee)', async function() {

    await this.exchangeproxy.setTransferProxy(accounts[0], { from: accounts[0] });

    //function is swapTokens(address _tokenFrom, address _tokenTo, uint256 _amount)
    // swap 25000 DAI for 22500 USDC (mocked)
    await this.mockdai.approve.sendTransaction(this.exchangeproxy.address, web3.utils.toBN('1000000000000000000000000'), { from: accounts[0] });

    // transfer all USDC mock balance to swap executor
    await this.mockusdc.transfer(this.mockexecutor.address, web3.utils.toBN('1000000000000'), { from: accounts[0] });
    expect((await this.mockusdc.balanceOf(accounts[0])).toString()).to.equal('0');

    const bytesData = [].concat(web3.utils.hexToBytes(this.mockexecutor.address), web3.utils.hexToBytes(this.mockexecutor.address), 
                        web3.utils.hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000000'), 
                        web3.utils.hexToBytes('0xec6cc0cc000000000000000000000000'), //func hash + padding for address of token from
                        web3.utils.hexToBytes(this.mockdai.address),
                        web3.utils.hexToBytes('0x000000000000000000000000'), //padding for address of token to
                        web3.utils.hexToBytes(this.mockusdc.address),
                        web3.utils.hexToBytes('0x00000000000000000000000000000000000000000000054B40B1F852BDA00000'));

    const txSwap = await this.exchangeproxy.executeSwap(this.mockdai.address, this.mockusdc.address, web3.utils.toBN('25000000000000000000000'), bytesData);

    truffleAssert.eventEmitted(txSwap, 'ExecuteSwap', (ev) => {
        return ev.user.toString() === accounts[0] &&
               ev.tokenIn.toString() === this.mockdai.address &&
               ev.tokenOut.toString() === this.mockusdc.address &&
               ev.amountIn.toString() === '25000000000000000000000' &&
               ev.amountOut.toString() === '22500000000';
    });

    // verify that amounts are correct and received
    expect((await this.mockusdc.balanceOf(accounts[0])).toString()).to.equal('22500000000');
  });

  it('should execute swap producing exchange of tokens (exchange fee)', async function() {

    await this.exchangeproxy.setTransferProxy(accounts[0], { from: accounts[0] });

    //function is swapTokens(address _tokenFrom, address _tokenTo, uint256 _amount)
    // swap 25000 DAI for 22500 USDC (mocked)
    //await this.mockdai.approve.sendTransaction(this.exchangeproxy.address, web3.utils.toBN('1000000000000000000000000'), { from: accounts[0] });
    await this.mockdai.transfer.sendTransaction(this.exchangeproxy.address, web3.utils.toBN('25000000000000000000000'), { from: accounts[0] });

    // transfer all USDC mock balance to swap executor
    await this.mockusdc.transfer(this.mockexecutor.address, web3.utils.toBN('1000000000000'), { from: accounts[0] });
    expect((await this.mockusdc.balanceOf(accounts[0])).toString()).to.equal('0');

    const bytesData = [].concat(web3.utils.hexToBytes(this.mockexecutor.address), web3.utils.hexToBytes(this.mockexecutor.address), 
                        web3.utils.hexToBytes('0x0000000000000000000000000000000000000000000000000000000000000000'), 
                        web3.utils.hexToBytes('0xec6cc0cc000000000000000000000000'), //func hash + padding for address of token from
                        web3.utils.hexToBytes(this.mockdai.address),
                        web3.utils.hexToBytes('0x000000000000000000000000'), //padding for address of token to
                        web3.utils.hexToBytes(this.mockusdc.address),
                        web3.utils.hexToBytes('0x00000000000000000000000000000000000000000000054B40B1F852BDA00000'));

    await truffleAssert.reverts(this.exchangeproxy.executeSwapDirect(accounts[1], this.mockusdc.address, this.mockdai.address, web3.utils.toBN('26000000000000000000000'), web3.utils.toBN('40000000000000000'), bytesData, { from: accounts[0] }), "SWAP_CALL_FAILED");
                    
    const txSwap = await this.exchangeproxy.executeSwapDirect(accounts[1], this.mockdai.address, this.mockusdc.address, web3.utils.toBN('25000000000000000000000'), web3.utils.toBN('40000000000000000'), bytesData);

    truffleAssert.eventEmitted(txSwap, 'ExecuteSwap', (ev) => {
        return ev.user.toString() === accounts[1] &&
               ev.tokenIn.toString() === this.mockdai.address &&
               ev.tokenOut.toString() === this.mockusdc.address &&
               ev.amountIn.toString() === '25000000000000000000000' &&
               ev.amountOut.toString() === '21600000000';
    });

    // verify that amounts are correct and received
    expect((await this.mockusdc.balanceOf(accounts[1])).toString()).to.equal('21600000000');
  });
});
