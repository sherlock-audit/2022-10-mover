// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Registry to perform whitelisting of contracts .call is made to (bridges, swap proxies)
interface IContractWhitelist{
    function isWhitelisted(address _targetAddress) external view returns(bool);
}
