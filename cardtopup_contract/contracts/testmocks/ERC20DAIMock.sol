// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";


/**
    @dev Mock of the DAI token to perform local test swaps
*/
contract ERC20DAIMock is ERC20("DAIMock", "TDAI") {

    /**
        @dev wallet to mint 1M tokens as initial supply for tests
     */
    address public founder;

    // inital amount to mint to founder
    uint public constant AMOUNT_INIT = 1000000 * 1e18;

    constructor(address _founder) {
        // address that deployed contract becomes initial founder
        founder = _founder;
        // mint tokens to founder
	    _mint(founder, AMOUNT_INIT);
    }

    // burn could be used in tests to clear some address' balance
    function burn(address _address, uint256 _amount) public {
        _burn(_address, _amount);
    }
}