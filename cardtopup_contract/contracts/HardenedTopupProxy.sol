// SPDX-License-Identifier: MIT
pragma solidity ^0.8.6;

///////////////////////////////////////////////////////////////////////////
//     __/|      
//  __////  /|   This smart contract is part of Mover infrastructure
// |// //_///    https://viamover.com
//    |_/ //     support@viamover.com
//       |/
///////////////////////////////////////////////////////////////////////////

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";

import "./interfaces/IExchangeProxy.sol";
import "./interfaces/IContractWhitelist.sol";
import "./interfaces/IAcrossBridgeSpokePool.sol";

import "./utils/RLPReader.sol";
import "./utils/SafeAllowanceResetUpgradeable.sol";

/**
    @dev HardenedTopupProxy is a transfer proxy contract for ERC20 and ETH card topups from (currently from L2 Polygon)
    - extract fees;
    - call token conversion if needed;
    - bridge to L1 card settlement relay;
    - non-custodial, not holding any funds;
    - fees are accumulated on this contract's balance (if fees enabled);

    Several considerations about the functions of this contract:
       - Security is important, esp. compared to gas costs on L2 (which are negligible for most L2s);
       - We try to avoid allowance-related attack vector by applying 2 required conditions before
         making a transfer of some ERC20 from user wallet (regardless of the operation):
           1. transfer is made only from msg.sender (so 3rd party cannot access other's funds), the only
              exceotion could be that transaction is initiated from trusted party;
           2. allowance is made to the amount requested in the operation (or only slightly more) --
              size check must pass otherwise revert, and allowance must be done recently, this is proved
              either by a trusted party with that specific role, or by prodiving proof so it could be
              verified by contract on-chain (this is technically limited to 256 most recent blocks though);
       - This contract does not hold any user funds, and is not intended to do so
       
       - Operations could be disabled at any time for security reasons (probably by automatic scanners);

       - 3rd party contracts used:
           - Bridging (Across and Synapse);
           - Swaps (1inch and 0x);
         all 3rd party addresses calls must pass whitelist contract registry check, if it fails, tx reverts.

    Approval timing check could be done using three approaches:
    1. without backend (on-chain):
       a. use permit() if token supports it. DAI-type permits would fail size check as they
          put allowance to 0xffff....ffff;
       b. verify using block hash
          - approve should be called within 256 blocks of the transaction called triggering this check;
          - caller must provide block number, tx index, and MPT proof so the tx could be verified
            using the block hash;
    2. with backend:
       - trusted signer address is provided (preset in contract) and an appropriate signed message
         is provided, stating that recent approval was performed;
    
    Approval size check
     - approval size must match the tolerance and decimals of the token being checked and must be larger
       than requested amount but smaller than tolerance treshold;
*/
contract HardenedTopupProxy is AccessControlUpgradeable, SafeAllowanceResetUpgradeable {
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;
    using AddressUpgradeable for address payable;
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;
    using ByteUtil for bytes;

    // provided by this contract to bridges/swaps contracts
    uint256 private constant ALLOWANCE_SIZE = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    // token address for non-wrapped eth
    address private constant ETH_TOKEN_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    // if greater than zero, this is a fractional amount (1e18 = 1.0) fee applied to all topups (after exchange to USDC)
    uint256 public topupFee;
    // if greater than zero, this is a fractional amount (1e18 = 1.0) fee applied to exchange operations with exchange proxy
    uint256 public exchangeFee;
    // allowance top boundary (in)
    uint256 private allowanceTreshold;
    // allowance max signature age (seconds)
    uint256 private allowanceSignatureTimespan;

    // minimum and maximum allowed amounts to perform topup (editable by admin, current minimum is ~25 USDC, maximum ~10000 USDC)
    uint256 private minAmount;
    uint256 private maxAmount;

    // exchange proxy/middleware contract (trusted)
    IExchangeProxy private exchangeProxyContract;

    // contract registry (when making 'call' for bridge addresses its checked against this trusted registry)
    IContractWhitelist private trustedRegistryContract;

    // address (EOA or contract) with single function to collect accumulated fees
    address private yieldDistributorAddress;

    // trusted execution wallets to provide signature of recent approval
    bytes32 public constant TRUSTED_EXETUTOR_ROLE = keccak256("TRUSTED_EXECUTION");

    // ability to immediately suspend contract functions for emergency cases (unpause by admin) for automated security systems
    bytes32 public constant TRUSTED_PAUSER_ROLE = keccak256("TRUSTED_PAUSER");

    // no topups are allowed if paused
    bool public paused;

    event CardTopup(address indexed account, address token, uint256 valueToken, uint256 valueUSDC, bytes32 _receiverHash);

    event BridgeTx(address indexed account, address token, uint256 amount, address bridge, address destination);

    // L1 Eth address for card topup settlement
    address private cardPartnerAddress;
    // Token that could be bridged and used for card top-up
    address private cardTopupToken;

    event FeeChanged(string indexed name, uint256 value);

    event EmergencyTransfer(address indexed token, address indexed destination, uint256 amount);

    function initialize() public initializer {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        // no need to initialize zero and false values
        // paused = false;
        // topupFee = 0;
        // exchangeFee = 0;
        // minAmount = 0;
        maxAmount = 10000000000;

        // 10% allowance tolerance treshold
        allowanceTreshold = 1_100_000_000_000_000_000;
    }

    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "admin only");
        _;
    }

    function setExchangeProxy(address _exchangeProxyContract) public onlyAdmin {
        exchangeProxyContract = IExchangeProxy(_exchangeProxyContract);
    }

    function setTrustedRegistry(address _trustedRegistryContract) public onlyAdmin {
        trustedRegistryContract = IContractWhitelist(_trustedRegistryContract);
    }

    function setAllowanceTreshold(uint256 _allowanceTreshold) public onlyAdmin {
        allowanceTreshold = _allowanceTreshold;
    }

    function setAllowanceSignatureTimespan(uint256 _allowanceSignatureTimespan) public onlyAdmin {
        allowanceSignatureTimespan = _allowanceSignatureTimespan;
    }

    function setYieldDistributor(address _tokenAddress, address _distributorAddress) public onlyAdmin {
        yieldDistributorAddress = _distributorAddress;
        // only yield to be redistributed should be present on this contract balance in baseAsset
        resetAllowanceIfNeeded(IERC20Upgradeable(_tokenAddress), _distributorAddress, ALLOWANCE_SIZE);
    }

    function setTopupFee(uint256 _topupFee) public onlyAdmin {
        topupFee = _topupFee;
        emit FeeChanged("topup", _topupFee);
    }

    function setExchangeFee(uint256 _exchangeFee) public onlyAdmin {
        exchangeFee = _exchangeFee;
        emit FeeChanged("exchange", _exchangeFee);
    }

    function setCardPartnerAddress(address _cardPartnerAddress) public onlyAdmin {
        cardPartnerAddress = _cardPartnerAddress;
    }

    function setCardTopupToken(address _topupToken) public onlyAdmin {
        cardTopupToken = _topupToken;
    }

    function setMinAmount(uint256 _minAmount) public onlyAdmin {
        minAmount = _minAmount;
    }

    function setMaxAmount(uint256 _maxAmount) public onlyAdmin {
        maxAmount = _maxAmount;
    }

    function setPaused(bool _paused) public onlyAdmin {
        paused = _paused;
    }

    function pauseOperation() public onlyAdmin {
        paused = true;
    }

    // this function is similar to emergencyTransfer, but relates to yield distribution
    // fees are not transferred immediately to save gas costs for user operations
    // so they accumulate on this contract address and can be claimed by yield distributor
    // when appropriate. Anyway, no user funds should appear on this contract, it
    // only performs transfers, so such function has great power, but should be safe
    // It does not require approval, so may be used by yield distributor to get fees from swaps
    // in different small token amounts
    function claimFees(address _token, uint256 _amount) public {
        require(msg.sender == yieldDistributorAddress, "yield distributor only");
        if (_token != ETH_TOKEN_ADDRESS) {
            IERC20Upgradeable(_token).safeTransfer(msg.sender, _amount);
        } else {
            payable(msg.sender).sendValue(_amount);
        }
    }

    // all Mover contracts that do not hold funds have this emergency function if someone occasionally
    // transfers ERC20 tokens directly to this contract
    // callable only by admin
    function emergencyTransfer(
        address _token,
        address _destination,
        uint256 _amount
    ) public onlyAdmin {
        if (_token != ETH_TOKEN_ADDRESS) {
            IERC20Upgradeable(_token).safeTransfer(_destination, _amount);
        } else {
            payable(_destination).sendValue(_amount);
        }
        emit EmergencyTransfer(_token, _destination, _amount);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // CROSS-CHAIN TOPUP MAIN INTERNAL FUNCTIONS
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////    

    function checkAllowance(address _token, uint256 _amount) view internal {
        require(IERC20Upgradeable(_token).allowance(msg.sender, address(this)) >= _amount, "insufficient allowance");
        require(IERC20Upgradeable(_token).allowance(msg.sender, address(this)) < _amount.mul(allowanceTreshold).div(1e18), "excessive allowance");
    }

    /**
        @dev process a topup (swap if needed and bridge to L1 where card settlement occurs) for arbitrary ERC20 or native token
        @param _bridgeType 0 == SYNAPSE, 1 == ACROSS
        @param _bridgeTxData for synapse bridge its address + bytes formed by their SDK/API, for Across bridge its only the 20 bytes its pool address
     */
    function _processTopup(address _beneficiary, address _token, uint256 _amount, uint256 _expectedMinimumReceived, bytes memory _convertData, uint256 _bridgeType, bytes memory _bridgeTxData, bytes32 _receiverHash) internal
    {
        // don't go further is contract function is paused (by admin or pauser)
        require(paused == false, "operations paused");

        // if execution passes to here, it means:
        // 1. operations are active;
        // 2. allowance check is passed, allowance is set and we can use funds from _beneficiary's address;
        // next steps are:
        // 1. transfer token to this contract or exchange proxy
        //    TODO (future version): check if token must be unwrapped by a partner
        //    (vault tokens, etc. that could not be swapped and should be unwrapped in some way)
        // 2. swap if needed and transfer USDC to this contract
        // 3. deduct topup fee (if needed)
        // 4. check allowance to the bridge contract
        // 5. check the bridge address is in the whitelist and perform a call to bridge

        if (_token == cardTopupToken) {
            // beneficiary is msg.sender (perform static check)
            IERC20Upgradeable(_token).safeTransferFrom(_beneficiary, address(this), _amount);

            uint256 feeAmount = _amount.mul(topupFee).div(1e18);

            // bridge from _beneficiary to card L1 relay
            bridgeAssetDirect(_amount.sub(feeAmount), _bridgeType, _bridgeTxData);

            emit CardTopup(_beneficiary, _token, _amount, _amount.sub(feeAmount), _receiverHash);
            return;
        }

        // conversion is required, perform swap through exchangeProxy
        if (_token != ETH_TOKEN_ADDRESS) {
            IERC20Upgradeable(_token).safeTransferFrom(_beneficiary, address(exchangeProxyContract), _amount);
        }

        // exchange proxy is trusted and would check swap provider on its own
        uint256 amountReceived =
            IExchangeProxy(address(exchangeProxyContract)).executeSwapDirect{value: msg.value}(
                address(this),
                _token,
                cardTopupToken,
                _amount,
                exchangeFee,
                _convertData
            );

        // this is sanity check from the client if the swap misbehaves
        require(amountReceived >= _expectedMinimumReceived, "minimum swap amount not met");

        if (topupFee != 0) {
            uint256 feeAmount = amountReceived.mul(topupFee).div(1e18);
            amountReceived = amountReceived.sub(feeAmount);
        }

        if (_bridgeType == 0) {
            // if using Synapse bridge and a swap was performed
            // because of Synapse bridge interface is off-chain
            // modify part of bridgeTxData to reflect new amount
            // in bridgeTxData, its layout is as following:
            // bytes   0..19 target address (topup relay on L1)
            // bytes  20..23 function signature
            // bytes  24..151 bridge tx params
            // bytes 152..183 min to mint
            // bytes 184..279 bridge tx params
            // bytes 280..311 min dy
            // bytes 312..407 bridge tx params
            // bytes 408..439 source amount
            // bytes 440..471 bridge tx params
            uint256 minMint = amountReceived.mul(950000).div(1000000); // 0.95 nUSD to mint
            uint256 minDy = amountReceived.mul(910000).div(1000000); // 0.91 expected to be received
            assembly {
                // first 32 bytes of 'bytes' is it's length, and after that it's contents
                // so offsets are 32+152=184, 32+280=312, 32+408=440
                mstore(add(_bridgeTxData, 184), minMint)
                mstore(add(_bridgeTxData, 312), minDy)
                mstore(add(_bridgeTxData, 440), amountReceived)
            }
        }

        // bridge from _beneficiary to card L1 relay
        bridgeAssetDirect(amountReceived, _bridgeType, _bridgeTxData);

        emit CardTopup(_beneficiary, _token, _amount, amountReceived, _receiverHash);
    }

    function bridgeAssetDirect(uint256 _amount, uint256 _bridgeType, bytes memory _bridgeTxData) internal {
        require(_amount >= minAmount, "minimum amount not met");
        require(_amount < maxAmount, "maximum amount exceeded");

        address targetAddress;
        assembly {
            targetAddress := mload(add(_bridgeTxData, 0x14))
        }

        // call method is very powerful, as it allows to call anything pretending to be the topup proxy
        // so we protect ourserves by allowing only the addresses we add to allowlist
        require(trustedRegistryContract.isWhitelisted(targetAddress), "call to non-trusted");

        resetAllowanceIfNeeded(IERC20Upgradeable(cardTopupToken), targetAddress, _amount);

        if (_bridgeType == 0)
        {
            bytes memory callData = _bridgeTxData.slice(20, _bridgeTxData.length - 20);
            (bool success, ) = targetAddress.call(callData);
            require(success, "BRIDGE_CALL_FAILED");
        } else if (_bridgeType == 1) {
            uint256 feePct;
            assembly {
                // offset 0x20 to data and 0x14 to tightly packed address, next 32 bytes expected are fee pct
                feePct := mload(add(_bridgeTxData, 0x34))
            }
            IAcrossBridgeSpokePool(targetAddress).deposit(cardPartnerAddress,
                cardTopupToken,
                _amount,
                1, // L1 Eth mainnet
                uint64(feePct), // max is 495_000_000_000_000_000 (49.5%) fee (bridge has 50% fee allowed as max)
                uint32(block.timestamp));
        } else {
            revert("unknown bridge");
        }

        emit BridgeTx(msg.sender, cardTopupToken, _amount, targetAddress, cardPartnerAddress);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////    
    // INTERNAL FUNCTIONS FOR TRUSTED SIGNATURE BASED ALLOWANCE CHECK
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /**
        @dev reconstruct a message to be verified (signed by trusted backend) that allowance is recent and of correct value
     */
    function constructMsg(bytes32 _addrhash, address _token, uint256 _amount, uint256 _timestamp) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("MOVER TOPUP ", _addrhash, " TOKEN ", _token, " AMOUNT ", _amount, " TS ", _timestamp));
    }

    /**
        @dev recover signer by ecrecover from a signature presented in bytes array
     */
    function recoverSigner(bytes32 message, bytes memory sig) internal pure returns (address)
    {
        require(sig.length == 65, "invalid sig length");

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
        if (v < 27) {
            v += 27;
        }

        return ecrecover(message, v, r, s);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////    
    // INTERNAL FUNCTIONS FOR MERKLE-PATRICIA-TRIE ALLOWANCE CHECK
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////    
    //
    // These functions are created to perform approval checks (approval timing) -- to verify that certain ERC20 
    // token's approve() indeed happened within 256 most recent blocks using on-chain proof.
    // There helper functions use MPT RLP-encoded proof which is matched against block hash (available
    // to smart contract), transaction is extracted from proof, RLP-decoded, sender, spender and allowance
    // amount are checked to be valid as well.
    //
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////    
  
    uint256 constant TX_ROOT_HASH_INDEX = 4;

    /**
        @dev structure to represent RLP-decoded transaction data extracted from proof (only used fields are preserved)
     */
    struct SignedTransaction {
        uint256 chainID;      // for EIP-1661 only
        address to;           // target ERC-20 contract (token)
        bytes data;           // used to check that method is approve, spender and amount
        uint256 v;            // signature checksum
        uint256 r;            // 1st signature component
        uint256 s;            // 2nd signature component
        bytes32 unsignedHash; // for extracting sender address
    }

    /**
      * @dev check if the RLP encoded item is empty (could be list or value byte sequence)
      * @notice In lists 0xc0 means empty list as additional condition
      */
    function isEmpty(RLPReader.RLPItem memory item, bool byteSequence) internal pure returns (bool) {
        if (item.len != 1) {
            return false;
        }
        uint8 b;
        uint memPtr = item.memPtr;
        assembly { b := byte(0, mload(memPtr)) }
        return b == 0x80 /* empty byte string */ || (!byteSequence && b == 0xc0 /* empty list */);
    }

    /**
     * @dev RLP encodes a list of RLP encoded byte byte strings.
     * @notice From: https://github.com/sammayo/solidity-rlp-encoder/blob/master/RLPEncode.sol.
     * @param self The list of RLP encoded byte strings.
     * @return The RLP encoded list of items in bytes.
     */
    function encodeList(RLPReader.RLPItem[] memory self) internal pure returns (bytes memory) {
        if (self.length == 0) {
            return new bytes(0);
        }

        uint len;
        uint i;
        for (i = 0; i < self.length; i++) {
            len += self[i].len;
        }

        bytes memory flattened = new bytes(len);
        uint flattenedPtr;
        assembly { flattenedPtr := add(flattened, 0x20) }

        for(i = 0; i < self.length; i++) {
            bytes memory item = self[i].toRlpBytes();
            
            uint listPtr;
            assembly { listPtr := add(item, 0x20)}

            ByteUtil.memcpy(listPtr, flattenedPtr, item.length);
            flattenedPtr += self[i].len;
        }
        
        return bytes.concat(encodeLength(flattened.length, 192), flattened);
    }

    /**
     * @dev Encode the first byte, followed by the `len` in binary form if `length` is more than 55.
     * @param len The length of the string or the payload.
     * @param offset 128 if item is string, 192 if item is list.
     * @return RLP encoded bytes.
     */
    function encodeLength(uint len, uint offset) private pure returns (bytes memory) {
        bytes memory encoded;
        if (len < 56) {
            encoded = new bytes(1);
            encoded[0] = bytes32(len + offset)[31];
        } else {
            uint lenLen;
            uint i = 1;
            while (len / i != 0) {
                lenLen++;
                i *= 256;
            }

            encoded = new bytes(lenLen + 1);
            encoded[0] = bytes32(lenLen + offset + 55)[31];
            for(i = 1; i <= lenLen; i++) {
                encoded[i] = bytes32((len / (256**(lenLen-i))) % 256)[31];
            }
        }
        return encoded;
    }

    /**
      * @dev decode RLP-endoded signed transaction (legacy or EIP-1559 London type)
        @return t transaction data structure that includes reconstructed unsigned tx and
             signature values that would allow to recover sender (tx signer)
      * @notice In lists 0xc0 means empty list as additional condition
      */
    function decodeSignedTx(bytes memory rlpSignedTx) internal pure returns (SignedTransaction memory t) {
        // if has prefix 0x2 its tx from London hardfork (0x1 Berlin is rare and not supported)
        if (uint8(rlpSignedTx[0]) != 0x2) {
            // legacy tx
            RLPReader.RLPItem[] memory fields = rlpSignedTx.toRlpItem().toList();
            
            require(!isEmpty(fields[3], false), 'contract creation tx proof');
            
            uint V = (fields[6].toUint() + 1) % 2; // in legacy txes clean chainID from this field, we need V for sender address recovery
            uint R = fields[7].toUint();
            uint S = fields[8].toUint();
            uint chainID = (fields[6].toUint() - 35) / 2; // EIP-155

            // 137 Polygon ChainID RLP-encoded, we would place appropriate Chain ID to check on every L2 contract instance
            bytes memory polygonChainId = '\x81\x89';
            bytes memory zeroValue = '\x80';
            fields[6] = polygonChainId.toRlpItem(); //encodeUint(chainID).toRlpItem(); // (for unsigned legacy tx V equals ChainID)
            fields[7] = zeroValue.toRlpItem(); //encoded value of 0, encodeUint(0).toRlpItem();
            fields[8] = zeroValue.toRlpItem(); //encoded value of 0, encodeUint(0).toRlpItem();

            t = SignedTransaction(
                chainID,
                fields[3].toAddress(), // to (token)
                fields[5].toBytes(), // tx data
                V, // V
                R, // R
                S, // S
                encodeList(fields).toRlpItem().rlpBytesKeccak256() // unsigned hash (for sender address recovery)
            );
        } else {
            // London tx
            RLPReader.RLPItem[] memory fields = rlpSignedTx.toRlpItemStripTxPrefix().toList();

            require(!isEmpty(fields[5], false), 'contract creation tx proof');

            // unsigned hash does not include V, R, S at all, so cut array length by 3
            uint V = fields[9].toUint();
            uint R = fields[10].toUint();
            uint S = fields[11].toUint();
            assembly { mstore(fields, sub(mload(fields), 3)) }

            t = SignedTransaction(
                fields[0].toUint(), // chainId
                fields[5].toAddress(), // to (token)
                fields[7].toBytes(), // tx data
                V, // V
                R, // R
                S, // S
                // unsigned tx should be encoded with same 0x2 prefix (London EIP-1559) as signed tx 
                keccak256(abi.encodePacked(uint8(0x2), encodeList(fields).toRlpItem().toRlpBytes())) // unsigned hash (for sender address recovery)
            );
        }
    }

    function decodeNibbles(bytes memory compact, uint skipNibbles) internal pure returns (bytes memory nibbles) {
        require(compact.length > 0);

        uint length = compact.length * 2;
        require(skipNibbles <= length);
        length -= skipNibbles;

        nibbles = new bytes(length);
        uint nibblesLength = 0;

        for (uint i = skipNibbles; i < skipNibbles + length; i += 1) {
            if (i % 2 == 0) {
                nibbles[nibblesLength] = bytes1((uint8(compact[i/2]) >> 4) & 0xF);
            } else {
                nibbles[nibblesLength] = bytes1((uint8(compact[i/2]) >> 0) & 0xF);
            }
            nibblesLength += 1;
        }

        assert(nibblesLength == nibbles.length);
    }

    function merklePatriciaCompactDecode(bytes memory compact) internal pure returns (bool isLeaf, bytes memory nibbles) {
        require(compact.length > 0);
        uint first_nibble = uint8(compact[0]) >> 4 & 0xF;
        uint skipNibbles;
        if (first_nibble == 0) {
            skipNibbles = 2;
            isLeaf = false;
        } else if (first_nibble == 1) {
            skipNibbles = 1;
            isLeaf = false;
        } else if (first_nibble == 2) {
            skipNibbles = 2;
            isLeaf = true;
        } else if (first_nibble == 3) {
            skipNibbles = 1;
            isLeaf = true;
        } else {
            // Not supposed to happen!
            revert();
        }
        return (isLeaf, decodeNibbles(compact, skipNibbles));
    }

    function sharedPrefixLength(uint xsOffset, bytes memory xs, bytes memory ys) internal pure returns (uint) {
        uint i;
        for (i = 0; i + xsOffset < xs.length && i < ys.length; i++) {
            if (xs[i + xsOffset] != ys[i]) {
                return i;
            }
        }
        return i;
    }

    struct Proof {
        uint256 kind;
        bytes rlpBlockHeader;
        bytes32 txRootHash;
        bytes mptKey;
        RLPReader.RLPItem[] stack;
    }

    function decodeProofBlob(bytes calldata proofBlob) internal pure returns (Proof memory proof) {
        RLPReader.RLPItem[] memory proofFields = proofBlob.toRlpItem().toList();
        bytes memory rlpTxIndex = proofFields[2].toRlpBytes();
        proof = Proof(
            proofFields[0].toUint(),
            proofFields[1].toRlpBytes(),
            bytes32(proofFields[1].toList()[TX_ROOT_HASH_INDEX].toUint()),
            decodeNibbles(rlpTxIndex, 0),
            proofFields[3].toList()
        );
    }

    uint8 constant private TX_PROOF_RESULT_PRESENT = 1;
    uint8 constant private TX_PROOF_RESULT_ABSENT = 2;

    function validateTxProof(
        bytes32 blockHash,
        bytes calldata proofBlob
    ) public pure returns (uint8 result, SignedTransaction memory t) {
        result = 0;
        Proof memory proof = decodeProofBlob(proofBlob);
        if (proof.kind != 1) {
            revert();
        }

        if (keccak256(proof.rlpBlockHeader) != blockHash) {
            revert();
        }

        bytes memory rlpTx = validateMPTProof(proof.txRootHash, proof.mptKey, proof.stack);

        if (rlpTx.length == 0) {
            // empty node
            result = TX_PROOF_RESULT_ABSENT;
        } else {
            result = TX_PROOF_RESULT_PRESENT;
            t = decodeSignedTx(rlpTx);
        }
    }

    /**
        @dev Computes the hash of the Merkle-Patricia-Trie hash of the input.
          Merkle-Patricia-Tries use a weird "hash function" that outputs
          *variable-length* hashes: If the input is shorter than 32 bytes,
          the MPT hash is the input. Otherwise, the MPT hash is the
          Keccak-256 hash of the input.
          The easiest way to compare variable-length byte sequences is
          to compare their Keccak-256 hashes.
        @param input The byte sequence to be hashed.
        @return Keccak-256(MPT-hash(input))
     */
    function mptHashHash(bytes memory input) internal pure returns (bytes32) {
        if (input.length < 32) {
            return keccak256(input);
        } else {
            return keccak256(abi.encodePacked(keccak256(abi.encodePacked(input))));
        }
    }

    /**
        @dev Validates a Merkle-Patricia-Trie proof.
          If the proof proves the inclusion of some key-value pair in the
          trie, the value is returned. Otherwise, i.e. if the proof proves
          the exclusion of a key from the trie, an empty byte array is
          returned.
        @param rootHash is the Keccak-256 hash of the root node of the MPT.
        @param mptKey is the key (consisting of nibbles) of the node whose
               inclusion/exclusion we are proving.
        @param stack is the stack of MPT nodes (starting with the root) that
               need to be traversed during verification.
        @return value whose inclusion is proved or an empty byte array for
                a proof of exclusion
     */
    function validateMPTProof(
        bytes32 rootHash,
        bytes memory mptKey,
        RLPReader.RLPItem[] memory stack
    ) internal pure returns (bytes memory value) {
        uint mptKeyOffset = 0;

        bytes32 nodeHashHash;
        bytes memory rlpNode;
        RLPReader.RLPItem[] memory node;

        if (stack.length == 0) {
            // Root hash of empty Merkle-Patricia-Trie
            require(rootHash == 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421);
            return new bytes(0);
        }

        // Traverse stack of nodes starting at root.
        for (uint i = 0; i < stack.length; i++) {

            // We use the fact that an rlp encoded list consists of some
            // encoding of its length plus the concatenation of its
            // *rlp-encoded* items.
            rlpNode = stack[i].toRlpBytes();
            // The root node is hashed with Keccak-256 ...
            if (i == 0 && rootHash != keccak256(rlpNode)) {
                revert();
            }
            // ... whereas all other nodes are hashed with the MPT
            // hash function.
            if (i != 0 && nodeHashHash != mptHashHash(rlpNode)) {
                revert();
            }
            // We verified that stack[i] has the correct hash, so we
            // may safely decode it.
            node = stack[i].toList();

            if (node.length == 2) {
                // Extension or Leaf node

                bool isLeaf;
                bytes memory nodeKey;
                (isLeaf, nodeKey) = merklePatriciaCompactDecode(node[0].toBytes());

                uint prefixLength = sharedPrefixLength(mptKeyOffset, mptKey, nodeKey);
                mptKeyOffset += prefixLength;

                if (prefixLength < nodeKey.length) {
                    // Proof claims divergent extension or leaf. (Only
                    // relevant for proofs of exclusion.)
                    // An Extension/Leaf node is divergent iff it "skips" over
                    // the point at which a Branch node should have been had the
                    // excluded key been included in the trie.
                    // Example: Imagine a proof of exclusion for path [1, 4],
                    // where the current node is a Leaf node with
                    // path [1, 3, 3, 7]. For [1, 4] to be included, there
                    // should have been a Branch node at [1] with a child
                    // at 3 and a child at 4.

                    // Sanity check
                    if (i < stack.length - 1) {
                        // divergent node must come last in proof
                        revert();
                    }

                    return new bytes(0);
                }

                if (isLeaf) {
                    // Sanity check
                    if (i < stack.length - 1) {
                        // leaf node must come last in proof
                        revert();
                    }

                    if (mptKeyOffset < mptKey.length) {
                        return new bytes(0);
                    }

                    return node[1].toBytes();
                } else { // extension
                    // Sanity check
                    if (i == stack.length - 1) {
                        // shouldn't be at last level
                        revert();
                    }

                    if (!node[1].isList()) {
                        // rlp(child) was at least 32 bytes. node[1] contains
                        // Keccak256(rlp(child)).
                        nodeHashHash = keccak256(node[1].toBytes());
                    } else {
                        // rlp(child) was at less than 32 bytes. node[1] contains
                        // rlp(child).
                        nodeHashHash = keccak256(node[1].toRlpBytes());
                    }
                }
            } else if (node.length == 17) {
                // Branch node

                if (mptKeyOffset != mptKey.length) {
                    // we haven't consumed the entire path, so we need to look at a child
                    uint8 nibble = uint8(mptKey[mptKeyOffset]);
                    mptKeyOffset += 1;
                    if (nibble >= 16) {
                        // each element of the path has to be a nibble
                        revert();
                    }

                    if (isEmpty(node[nibble], true)) {
                        // Sanity
                        if (i != stack.length - 1) {
                            // leaf node should be at last level
                            revert();
                        }

                        return new bytes(0);
                    } else if (!node[nibble].isList()) {
                        nodeHashHash = keccak256(node[nibble].toBytes());
                    } else {
                        nodeHashHash = keccak256(node[nibble].toRlpBytes());
                    }
                } else {
                    // we have consumed the entire mptKey, so we need to look at what's contained in this node.

                    // Sanity
                    if (i != stack.length - 1) {
                        // should be at last level
                        revert();
                    }

                    return node[16].toBytes();
                }
            }
        }
    }

    uint32 constant APPROVE_METHOD_ID = 0x095ea7b3;

    function checkApprove(bytes memory txdata) view internal {
        // check method is approve
        uint32 methodId;
        assembly { methodId := mload(add(txdata, 0x4)) }
        require(methodId == APPROVE_METHOD_ID, "method mismatch");

        // check spender is this contract
        address spender;
        assembly { spender := div(mload(add(add(txdata, 0x20), 0x10 /* 4 func sig + 12 left padding in uint256 word */)), 0x1000000000000000000000000) }
        require(spender == address(this), "spender mismatch");
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////    
    // PUBLIC (APP CALLABLE) TOP-UP FUNCTIONS
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////    
    // Flow for bridged topup procedure:
    // - allowance check
    //   - native token does not have allowance and goes to topup permit method with empty permit (only for this case);
    //   - if token supports permit, user signs permit and calls topup permit method;
    //   - if token does not support permit, user calls backend to check if there was recent enough approval
    //     with value matching topup amount in target token, there are 3 cases:
    //     - if approve is not present, too small, too large or too old, user makes approve tx with proper amount and repeats
    //     - if approve is for proper amount and recent enough, server provides signature from EOA having 'TRUSTED_EXECUTOR' role
    //     - if backend is not available, 500 server error, etc. we fallback to client-on-chain proof of allowance
    //       client makes approve tx with proper amount, remembers block and tx index, constructs proof of approve tx
    //       and passes to the topup = MPT proof method, resulting in on-chain check for approve (we are limited to 256 most
    //       recent blocks by solidity runtime design for this case)
    // - if not USDC token, transfer and swap native (or ERC20) token to USDC
    // - execute bridge to relay on L1 after which settlement on card would occur
    // - receiver hash can be empty (it used only for event emitting on-chain:
    //   - if receiver hash is empty, then sender address performs topup for card associated with his/her address);
    //   - receiver can be a keccak32(<receiver tag string>), it would be resolved upon settlement to topup card
    //     that is associated with tag;
    //   - receiver can be a keccak32 of a message constructed for tag topup by trusted backend (for single-time use),
    //     in such case tag cannot be recovered from the hash to stay private, and the hash can be also treated as
    //     proof if needed, that the address made topup request (contents of hashed message should match transaction content)
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////    

    /**
        @dev Top-up card using native token or ERC20 token supporting permit
     */
    function CardTopupPermit(address _token, uint256 _amount, bytes calldata _permit, uint256 _expectedMinimumReceived, bytes memory _convertData, uint256 _bridgeType, bytes memory _bridgeTxData, bytes32 _receiverHash) public payable {
        // this snippet is borrowed from 1inch contracts
        // but encodeWithSelector is replaced with encodePacked (how it worked in their code?) https://github.com/1inch/1inch-v2-contracts/blob/v2.1/contracts/OneInchExchange.sol#L173
        if (_permit.length == 32 * 7) {
            // solhint-disable-next-line avoid-low-level-calls
            (bool success, /*bytes memory result*/) = address(_token).call(abi.encodePacked(IERC20PermitUpgradeable.permit.selector, _permit));
            if (!success) {
                revert("permit call failed");
            }
        }

        if (_token != ETH_TOKEN_ADDRESS) {
            checkAllowance(_token, _amount);
        }

        _processTopup(msg.sender, _token, _amount, _expectedMinimumReceived, _convertData, _bridgeType, _bridgeTxData, _receiverHash);
    }

    /**
        @dev Top-up card using signature verifying recent approval by a trusted party (backend)
     */
    function CardTopupTrusted(address _token, uint256 _amount, uint256 _timestamp, bytes calldata _signature, uint256 _expectedMinimumReceived, bytes memory _convertData, uint256 _bridgeType, bytes memory _bridgeTxData, bytes32 _receiverHash) public {
        bytes32 message = constructMsg(keccak256(abi.encodePacked(msg.sender)), _token, _amount, _timestamp);
        address signer = recoverSigner(message, _signature);
        require(hasRole(TRUSTED_EXETUTOR_ROLE, signer), "wrong signature");
        require(block.timestamp - _timestamp < allowanceSignatureTimespan);

        checkAllowance(_token, _amount);

        _processTopup(msg.sender, _token, _amount, _expectedMinimumReceived, _convertData, _bridgeType, _bridgeTxData, _receiverHash);
    }

    /**
        @dev Top-up card using on-chain verification (256 recent blocks are available)
          using MPT-proof constructed by a webapp or any external tool
     */
    function CardTopupMPTProof(address _token, uint256 _amount, uint256 _blockNumber, bytes calldata _proofBlob, uint256 _expectedMinimumReceived, bytes memory _convertData, uint256 _bridgeType, bytes memory _bridgeTxData, bytes32 _receiverHash) public {
        require(block.number - _blockNumber < 256, "block too old");
        bytes32 blockHash = blockhash(_blockNumber);

        (uint8 result, SignedTransaction memory t) = validateTxProof(blockHash, _proofBlob);
        require(result == TX_PROOF_RESULT_PRESENT, "proof failed");

        address ecsender = ecrecover(t.unsignedHash, uint8(t.v + 27), bytes32(t.r), bytes32(t.s));
        require(ecsender == msg.sender, "sender mismatch");

        checkApprove(t.data);

        // check that token is correct
        require(t.to == _token, "token mismatch");

        // check that chainID is correct
        require(t.chainID == 137, "chain id mismatch");
        
        // we check 'current' allowance state (ignoring the value in the provided approve tx proof)
        //uint256 approveamount = toUint256(t.data, 36);
        checkAllowance(_token, _amount);

        _processTopup(msg.sender, _token, _amount, _expectedMinimumReceived, _convertData, _bridgeType, _bridgeTxData, _receiverHash);
    }
}
