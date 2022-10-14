// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Interface to represent across bridge spoke pool on L2
interface IAcrossBridgeSpokePool {
    function deposit(
        address recipient,
        address originToken,
        uint256 amount,
        uint256 destinationChainId,
        uint64 relayerFeePct,
        uint32 quoteTimestamp) payable external;
}
