// SPDX-License-Identifier: MIT

pragma solidity ^0.8.6;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

/**
    @dev this is non-standard for on-chain usage, but for mock purposes it's fine
 */
interface IERC20Extended is IERC20 {
    function decimals() external view returns (uint8);
}

/**
    @dev mock of the swap executor (from 0x project) to test swap execution locally
      exchanges mocked DAI to mocked USDC for rate of 0.9 (in fact, any token with rate of 0.9
      taoking decimals difference into account)
  */
contract TokenSwapExecutorMock {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    address private constant ETH_TOKEN_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    // payable fallback to receive ETH for tests
    receive() external payable {
    }

    /**
        @dev simulate a swap of ERC20 token or native token to another ERC20 token or native token
          takes decimals value into consideration, should have enough amount of target ERC20 token
          or native token to perform a swap sim. Rate of exchange is fixed to 0.9.
          Contract or EOA calling this method should ensure to provide value or have set allowance
          for this contract.
     */
    function swapTokens(address _tokenFrom, address _tokenTo, uint256 _amount) payable public {

        uint256 fromDecimals = 0;
        if (_tokenFrom == ETH_TOKEN_ADDRESS) {
            fromDecimals = 18;
        } else {
            fromDecimals = IERC20Extended(_tokenFrom).decimals();
        }

        uint256 toDecimals = 0;
        if (_tokenTo == ETH_TOKEN_ADDRESS) {
            toDecimals = 18;
        } else {
            toDecimals = IERC20Extended(_tokenTo).decimals();
        }

        if(_tokenFrom != ETH_TOKEN_ADDRESS) {
          IERC20(_tokenFrom).safeTransferFrom(msg.sender, address(this), _amount);
        } else {
          require(msg.value == _amount, "(swapmock) insufficient ETH provided");
        }

        uint256 amountToGive = _amount;

        // process decimals difference and
        // calculate amount to provide of target token
        if (fromDecimals > toDecimals) {
            uint256 decimalsToCutoff = fromDecimals - toDecimals;
            amountToGive = amountToGive.div(10 ** decimalsToCutoff);
        } else if (fromDecimals < toDecimals) {
            uint256 decimalsToAdd = toDecimals - fromDecimals;
            amountToGive = amountToGive.mul(10 ** decimalsToAdd);
        }

        // rate is always 0.9 between tokens
        // decimals are processed first for better precision
        amountToGive = amountToGive.mul(9).div(10);

        if (_tokenTo != ETH_TOKEN_ADDRESS) {
            IERC20(_tokenTo).safeTransfer(msg.sender, amountToGive);
        } else {
            require(amountToGive > 0, "amount to give is zero");
            require(amountToGive <= address(this).balance, "not enough ETH on swap mock");
            (bool success, ) = msg.sender.call{ value: amountToGive }("");
            require(success, "ETH transfer failed");
            //msg.sender.transfer(amountToGive); -- won't work as gas stipend doesn't fit upgradeable contracts
        }
    }
}