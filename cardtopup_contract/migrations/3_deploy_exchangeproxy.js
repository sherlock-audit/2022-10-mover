const ExchangeProxy = artifacts.require("ExchangeProxy");

module.exports = function (deployer) {
  deployer.deploy(ExchangeProxy);
};
