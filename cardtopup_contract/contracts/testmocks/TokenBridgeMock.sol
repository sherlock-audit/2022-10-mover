// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import "../interfaces/IAcrossBridgeSpokePool.sol";

/**
    @dev Mock of the bridge implementation to perform local test bridging simulation.
         ERC20 tokens remain on this contract balance and event is emitted.
 */
contract TokenBridgeMock is IAcrossBridgeSpokePool {
    using SafeERC20 for IERC20;
    
    event AssetsBridged(address recipient, address token, uint256 amount, uint256 destChainId, uint256 relayerFee, uint32 quoteTimestamp);

    constructor() {
    }

    // take the funds and emit event
    function deposit(address recipient, address originToken, uint256 amount, uint256 destinationChainId, uint64 relayerFeePct, uint32 quoteTimestamp) public payable override {
        // transfer ERC20 to this contract
        IERC20(originToken).safeTransferFrom(msg.sender, address(this), amount);
        // emit event
        emit AssetsBridged(recipient, originToken, amount, destinationChainId, relayerFeePct, quoteTimestamp);
    }
}
