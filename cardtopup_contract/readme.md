Mover Topup proxy
=================

main contract: `contracts/HardenedTopupProxy.sol`

The single goal of a contract is to get user funds (native token or ERC-20 token),
swap it to USDC (PoS USDC on Polygon) and bridge it to specified static address on L1 Eth,
on which user debit card settlement would be initiated.

The settlement process on L1 is off-chain and out of scope of the smart contracts.
If the proper event would be generated for card top-up, it would be further processed
by backend infrastructure.

None of the contracts is designed to hold user funds.

One of the attack vectors we want to avoid is enforce limited allowance (as this contract
version should be deployed on L2s, gas costs are non-critical), so that user should
place allowance that is sufficient, but not uint(-1)/max uint256 and recent enough.
This is solved by 3 possible ways (some may be removed in the future):
1. Use permit() (not DAI-like permit, as it provides 0xff..ff allowance) for tokens that support it;
2. Use trusted backend that would check that allowance matches topup amount and was recent enough
   (backend is out of scope of the contracts);
3. Use available block headers (256 most recent) in Solididty and provide proof that could be
   verified (Python utility to generate proofs for Polygon network is provided for convenience);

Only 3 non-view methods are public in the HardenedTopupProxy:
- CardTopupPermit();
- CardTopupTrusted();
- CardTopupMPTProof();

Tests are being constructed, but local testing is very complicated, due to involvement of:
- token swap through aggregator contract call;
- proof construction (in progress);
- bridging contracts call;

Solidity 0.8.6 does not need SafeMath library to handle overflows, but it is convenient
to have syntax used for a long time and explicit operator precedence (this is subjective of course).


### Polygon network contracts to be interacted via 'call'-s (would be whitelisted):

Swap aggregator proxies:

0x Proxy
https://polygonscan.com/address/0xdef1c0ded9bec7f1a1670819833240f027b25eff

1inch Proxy
https://polygonscan.com/address/0x1111111254fb6c44bac0bed2854e76f90643097d

Bridge proxies:

Synapse
https://polygonscan.com/address/0x1c6aE197fF4BF7BA96c66C5FD64Cb22450aF9cC8

Across
https://polygonscan.com/address/0x69b5c72837769ef1e7c164abc6515dcff217f920


### Cross-chain contract differences

Contracts provided here are aimed to be deployed on L2 networks, provided version
is aimed and was tested in Polygon (chainID 137).

The expected code changes between L2 networks are parameters provided in
constructor (initializer) or HardenedTopupProxy.sol: chainID value as uint
and as RLP-encoded bytes for various checks.

L1 topup contract version would not have any bridging function called, on line 380

    bridgeAssetDirect(amountReceived, _bridgeType, _bridgeTxData);

is changed to

    IERC20Upgradeable(cardTopupToken).safeTransfer(cardPartnerAddress, _amount);

bridgeAssetDirect() function could be removed from L1 contract altogether.


### Overall topup flow (for reference)

Draft schema could be found in /doc directory.

TopupFlowPt1.pdf contains interaction between app and reviewed contracts;


### Tests

Tests are provided to cover the main 3 flows, please ensure that a truffle
seed phrase is provided in the TopupProxyPermitFlow.test.js on line 22
(to allow permit signing).

Truffle version should for now be 5.4.29 or lower, otherwise block header
contains baseFeePerGas while its hash is being calculated using legacy
structure (probably a bug).

