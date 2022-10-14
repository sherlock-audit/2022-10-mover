// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Interface to represent middleware contract for swapping tokens
interface IExchangeProxy {
    // returns amount of 'destination token' that 'source token' was swapped to
    // NOTE: Exchange proxy grants allowance to arbitrary address (with call to contract that could be forged) and should not hold any funds

    // funds are taken from sender address and target tokens are transferred to it
    function executeSwap(address tokenFrom, address tokenTo, uint256 amount, bytes calldata data) payable external returns(uint256);
    // funds are transferred to exchange proxy beforehand, are used from it and target tokens are returned to beneficiary
    function executeSwapDirect(address beneficiary, address tokenFrom, address tokenTo, uint256 amount, uint256 fee, bytes calldata data) payable external returns(uint256);
}
