// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Interface to represent Across bridge spoke pool on L2
interface IAcrossBridgeSpokePool {
    // recipient is the target address in the outgoing bridge tx in target chain (this is settlement forwarder contract)
    // origin token is the token address in the source chain
    // amount is the source token amount
    // destinationChainId is 1 in the use case of card topup (L1 Eth)
    // relayerFeePct is the fee amount that bridge is allowed to charge for bridging (depends on target chain gas price)
    // quoteTimestamp (relates for fee percentage) should be recent enough (10 minutes check in bridge code)
    function deposit(
        address recipient,
        address originToken,
        uint256 amount,
        uint256 destinationChainId,
        uint64 relayerFeePct,
        uint32 quoteTimestamp) payable external;
}
