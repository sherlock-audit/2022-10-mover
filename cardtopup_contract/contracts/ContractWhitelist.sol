// SPDX-License-Identifier: MIT
pragma solidity ^0.8.6;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

import "./interfaces/IContractWhitelist.sol";

/**
    @dev A simple allowlist registry maintained by a trusted party to keep
      a list of trusted addresses, upon which a 'call' method or other interactions
      could take place.

      Should be maintained by security admins and have restricted access (at least though 
      multi-sig).
 */
contract ContractWhitelist is AccessControlUpgradeable, IContractWhitelist {
    mapping(address => bool) whitelist;

    // events to track adding or removing items (should be monitored by security backend)
    event AddedToWhitelist(address indexed targetAddress);
    event RemovedFromWhitelist(address indexed targetAddress);

    // this contract uses role-based access, so init the default admin role to the
    // contract creator. this is high-privileged role and should be protected
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

    /**
        @dev used by main contracts (topup proxy, exchange proxy) to determine, whether
          a call to some external 3rd party contract is allowed by this whitelist.
          No external call/delegatecall should be done without this additional check.
     */
    function isWhitelisted(address _targetAddress) public view override returns(bool) {
        return whitelist[_targetAddress];
    }
}
