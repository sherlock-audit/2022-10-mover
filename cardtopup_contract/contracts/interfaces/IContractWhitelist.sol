// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Registry to perform whitelisting of contracts .call is made to (bridges, swap proxies)
interface IContractWhitelist{
    // method to check if a certain address is considered a trusted contract
    function isWhitelisted(address _targetAddress) external view returns(bool);
}
