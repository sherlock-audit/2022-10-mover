// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";


/**
    @dev Mock of the USDC token to perform local test swaps
*/
contract ERC20USDCMock is ERC20("USDCMock", "TUSDC"), ERC20Permit("USDCMock") {

    /**
        @dev wallet to mint 1M tokens as initial supply for tests
     */
    address public founder;

    // inital amount to mint to founder
    uint public constant AMOUNT_INIT = 1000000 * 1e6;

    constructor(address _founder) {
        // address that deployed contract becomes initial founder
        founder = _founder;
        // mint tokens to founder
	    _mint(founder, AMOUNT_INIT);
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }
}