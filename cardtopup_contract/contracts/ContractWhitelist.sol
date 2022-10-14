// SPDX-License-Identifier: MIT
pragma solidity ^0.8.6;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

import "./interfaces/IContractWhitelist.sol";

/**
    @dev A simple allowlist registry maintained by a trusted party to keep
      a list of trusted addresses, upon which a 'call' method or other interactions
      could take place
 */
contract ContractWhitelist is AccessControlUpgradeable, IContractWhitelist {
    mapping(address => bool) whitelist;

    event AddedToWhitelist(address indexed targetAddress);
    event RemovedFromWhitelist(address indexed targetAddress);

    function initialize() public initializer {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    function add(address _targetAddress) public {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "admin only");
        whitelist[_targetAddress] = true;
        emit AddedToWhitelist(_targetAddress);
    }

    function remove(address _targetAddress) public {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "admin only");
        whitelist[_targetAddress] = false;
        emit RemovedFromWhitelist(_targetAddress);
    }

    function isWhitelisted(address _targetAddress) public view override returns(bool) {
        return whitelist[_targetAddress];
    }
}
