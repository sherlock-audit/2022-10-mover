# Mover contest details

- 25,000 USDC main award pot
- Join [Sherlock Discord](https://discord.gg/MABEWyASkp)
- Submit findings using the issue page in your private contest repo (label issues as med or high)
- [Read for more details](https://docs.sherlock.xyz/audits/watsons)
- Starts October 18, 2022 15:00 UTC
- Ends October 25, 2022 15:00 UTC

# Resources

- [Website](https://viamover.com/)
- [Knowledge Center](https://faq.viamover.com/)
- [Twitter](https://twitter.com/viaMover)

# Audit scope

The single goal of the contracts is to get user funds (native token or ERC-20 token),
swap it to USDC (PoS USDC on Polygon) and bridge it to specified static address on L1 Eth,
on which user debit card settlement would be initiated.

```
ExchangeProxy.sol
RLPReader.sol
SafeAllowanceReset.sol
ByteUtil.sol
SafeAllowanceResetUpgradeable.sol
HardenedTopupProxy.sol
ContractWhitelist.sol
```

# About Mover

Mover is building the web3 payment card primitives platform. We aim to help projects
build on top/with us to bring their use cases to real world. One card for all crypto
natives: those who contribute to a DAO, those who trade on DEXs, those who trade
decentralised options, those who collect NFTs, those who mint NFTs, those who create
NFTs, and many more. We are here to create THE web3 card.
