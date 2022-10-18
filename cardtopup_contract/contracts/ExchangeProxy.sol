// SPDX-License-Identifier: MIT
pragma solidity ^0.8.6;

///////////////////////////////////////////////////////////////////////////
//     __/|      
//  __////  /|   This smart contract is part of Mover infrastructure
// |// //_///    https://viamover.com
//    |_/ //     support@viamover.com
//       |/
///////////////////////////////////////////////////////////////////////////

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/Address.sol";

import "./interfaces/IExchangeProxy.sol";
import "./interfaces/IContractWhitelist.sol";
import "./utils/SafeAllowanceReset.sol";
import "./utils/ByteUtil.sol";

/**
   @dev Exhange proxy is a middleware contract that acts as an abstraction layer for tokens exchange
   (ERC20 tokens and ETH)

   The current implementation is tested compatible with 0x or 1inch API for performing actual swap, as they are aiming for
   best execution, there's no complex logic regarding that for now.

   Exchange occurs in the following steps:
   1. This contract is provided with amount of tokens on its address directly by Transfer or Topup proxy
      (thus does not requiring any allowance calls) for executeSwapDirect or it should have allowance
      if swapping through executeSwap;
   2. This contract is provided with data of how order is going to be routed (bytes swalCallData)
   3. 0x or 1inch order routing usually requires that this contract should allow that address to spend
      its tokens (address should be in the whitelist registry);
   4. The address that performs the swap is called with swapdata set;
   5. If swap is successful, this contract transfers tokens directly to beneficiary or
      back to the transfer/topup proxy contract;
   6. Appropriate event is emitted with swap details;
   7. Exchange/swap fees (if applicable) are staying on this contract address.

   This contract is inter-changeable and is not upgradeable.
*/
contract ExchangeProxy is AccessControl, IExchangeProxy, SafeAllowanceReset
{
    using SafeMath for uint256;
    using SafeERC20 for IERC20;
    using Address for address payable;

    uint256 private constant ALLOWANCE_SIZE = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    // token address for non-wrapped eth
    // (this matches how 0x and 1inch encode native token)
    address private constant ETH_TOKEN_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    // yield distributor
    // NOTE: to keep overhead for users minimal, fees are not transferred
    // immediately, but left on this contract balance, yieldDistributor can reclaim them
    address private yieldDistributorAddress;

    // transfer/topup proxy, methods are restricted to it for security reasons (and to allow direct transits to save gas, using single allowance point)
    address private transferProxyAddress;

    // trusted address registry of contracts, which are allowed to triggered using call method
    IContractWhitelist private trustedRegistryContract;

    // event that is used to monitor swaps, contains actual in-out tokens and amounts
    event ExecuteSwap(address indexed user, address indexed tokenIn, address tokenOut, uint256 amountIn, uint256 amountOut);

    // event that is triggered if amdin retrieves funds from this contract using EmenergencyTransfer method
    event EmergencyTransfer(address indexed token, address indexed destination, uint256 amount);

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    /**
        @dev modifier to allow only DEFAULT_ADMIN_ROLE access to certain methods
     */
    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "admin only");
        _;
    }

    /**
        @dev executeSwap is a wrapper for the executeSwapDirect method that makes
          ERC20 transfer from sender to this contract address beforehand
     */
    function executeSwap(
        address _tokenFrom,
        address _tokenTo,
        uint256 _amount,
        bytes memory _data
    ) public payable override returns (uint256) {
        // native token doesn't need to be transferred explicitly, it's in tx.value
        if (_tokenFrom != ETH_TOKEN_ADDRESS) {
            IERC20(_tokenFrom).safeTransferFrom(msg.sender, address(this), _amount);
        }
        // after token is transferred to this contract, call actual swap
        return executeSwapDirect(msg.sender, _tokenFrom, _tokenTo, _amount, 0, _data);
    }

    /**
        @dev ececuteSwapDirect is the main method of this contract, it performs decoding
          of swap aggregator/executor address, provides allowance to it and makes a call.
          It is assumed that source ERC20 token is on this contract balance (or tx.value is
          provided in case of native token, thus this method is marked payable)
     
          data is an arbitrary construction, that can be supplied if swap request is initiated
          off-chain (it may be required or may be empty, depending on implementation)
          TODO: WE GENERALLY DON'T TAKE RESPONSIBILITY OF CONTRACT PASSED IN THE DATA SECTION
              THAT IS PROVIDED BY 0x/1inch INFRASTRUCTURE, but we check target contract address
              -- this contract would perform check for expected minimum amount
              -- this contract performs call operation with arbitrary data:
                 -- no reentrancy;
                 -- this contract is a layer of security and does not have abilities except swap
         for current implementation, a 0x.org services are used to perform execution
         this contract would provice allowance by itself if needed, and tokens to be swapped
         have to be on its balance before
         data is unfolded into following structure in current implementation:
         bytes offset
            [ 0..19] address to call to perform swap
            [20..39] allowance target to perform swap
            [40..61] value of ETH to pass (if we swapping native token)
            [62...]  data section passed for swap call
         swap that directly transfers swapped tokens to beneficiary, and amounts should be present on this contract
         this contract should contain only exchange fees (if enabled) other funds are tranferred within single transaction
    */
    function executeSwapDirect(
        address _beneficiary,
        address _tokenFrom,
        address _tokenTo,
        uint256 _amount,
        uint256 _exchangeFee,
        bytes memory _data
    ) public payable override returns (uint256) {
        require(msg.sender == transferProxyAddress, "transfer proxy only");

        // extract values from bytes array provided
        address executorAddress;
        address spenderAddress;
        uint256 ethValue;

        bytes memory callData = ByteUtil.slice(_data, 72, _data.length - 72);
        assembly {
            executorAddress := mload(add(_data, add(0x14, 0)))
            spenderAddress := mload(add(_data, add(0x14, 0x14)))
            ethValue := mload(add(_data, add(0x20, 0x28)))
        }

        // allow spender to transfer tokens from this contract
        if (_tokenFrom != ETH_TOKEN_ADDRESS && spenderAddress != address(0)) {
            require(trustedRegistryContract.isWhitelisted(spenderAddress), "allowance to non-trusted");
            resetAllowanceIfNeeded(IERC20(_tokenFrom), spenderAddress, _amount);
        }

        // remember the actual balance of target token (fees could reside on this contract balance)
        uint256 balanceBefore = 0;
        if (_tokenTo != ETH_TOKEN_ADDRESS) {
            balanceBefore = IERC20(_tokenTo).balanceOf(address(this));
        } else {
            balanceBefore = address(this).balance;
        }

        // regardless of stated amount, the ETH value passed to exchange call must be provided to the contract
        require(msg.value >= ethValue, "insufficient ETH provided");

        // don't allow to call non-trusted addresses
        require(trustedRegistryContract.isWhitelisted(executorAddress), "call to non-trusted");

        // ensure no state passed, no reentrancy, etc.
        (bool success, ) = executorAddress.call{value: ethValue}(callData);
        require(success, "SWAP_CALL_FAILED");

        // always rely only on actual amount received regardless of called parameters
        uint256 amountReceived = 0;
        if (_tokenTo != ETH_TOKEN_ADDRESS) {
            amountReceived = IERC20(_tokenTo).balanceOf(address(this));
        } else {
            amountReceived = address(this).balance;
        }
        amountReceived = amountReceived.sub(balanceBefore);

        require(amountReceived > 0, "zero amount received");

        // process exchange fee if present (in deposit we get pool tokens, so process fees after swap, here we take fees in source token)
        // fees are left on this contract address and are harvested by yield distributor
        //uint256 feeAmount = amountReceived.mul(_exchangeFee).div(1e18);
        amountReceived = amountReceived.sub(
            amountReceived.mul(_exchangeFee).div(1e18)
        ); // this is return value that should reflect actual result of swap (for deposit, etc.)

        if (_tokenTo != ETH_TOKEN_ADDRESS) {
            //send received tokens to beneficiary directly
            IERC20(_tokenTo).safeTransfer(_beneficiary, amountReceived);
        } else {
            //send received eth to beneficiary directly
            payable(_beneficiary).sendValue(amountReceived);
            // payable(_beneficiary).transfer(amountReceived);
            // should work for external wallets (currently is the case)
            // but wont work for some other smart contracts due to gas stipend limit
        }

        emit ExecuteSwap(_beneficiary, _tokenFrom, _tokenTo, _amount, amountReceived);
        
        // amount received is used to check minimal amount condition set by calling app from topup proxy contract
        return amountReceived;
    }

    /**
        @dev swap calls are restricted only to topup proxy, which is set using this method
     */
    function setTransferProxy(address _transferProxyAddress) public onlyAdmin {
        transferProxyAddress = _transferProxyAddress;
    }

    /**
        @dev to save gas costs during withdrawals, etc, yield harvested (and it should be only yield)
          is stored on this contract balance. Yield distributor contract should have permission
          to get tokens from this contract
    */
    function setYieldDistributor(address _tokenAddress, address _distributorAddress) public onlyAdmin {
        yieldDistributorAddress = _distributorAddress;
        // only yield to be redistributed should be present on this contract in baseAsset (or other tokens if swap fees)
        // so no access to lp tokens for the funds invested
        resetAllowanceIfNeeded(IERC20(_tokenAddress), _distributorAddress, ALLOWANCE_SIZE);
    }

    function setTrustedRegistry(address _trustedRegistryContract) public onlyAdmin {
        trustedRegistryContract = IContractWhitelist(_trustedRegistryContract);
    }

    /**
        @dev this function is similar to emergencyTransfer, but relates to yield distribution
          fees are not transferred immediately to save gas costs for user operations
          so they accumulate on this contract address and can be claimed by yield distributor
          when appropriate. Anyway, no user funds should appear on this contract, it
          only performs transfers, so such function has great power, but should be safe
     */
    function claimFees(address _token, uint256 _amount) public {
        require(msg.sender == yieldDistributorAddress, "yield distributor only");
        if (_token != ETH_TOKEN_ADDRESS) {
            IERC20(_token).safeTransfer(msg.sender, _amount);
        } else {
            payable(msg.sender).sendValue(_amount);
        }
    }

    /**
        @dev all contracts that do not hold funds have this emergency function if someone occasionally
          transfers ERC20 tokens directly to this contract
          callable only by owner (admin)
    */
    function emergencyTransfer(address _token, address _destination, uint256 _amount) public onlyAdmin {
        if (_token != ETH_TOKEN_ADDRESS) {
            IERC20(_token).safeTransfer(_destination, _amount);
        } else {
            payable(_destination).sendValue(_amount);
        }
        emit EmergencyTransfer(_token, _destination, _amount);
    }
}
