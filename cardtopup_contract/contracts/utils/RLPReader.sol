// SPDX-License-Identifier: Apache-2.0
import "./ByteUtil.sol";

/*
* @author Hamdi Allam hamdi.allam97@gmail.com
* Please reach out with any questions or concerns
*/
pragma solidity ^0.8.6;

library RLPReader {
    // constants for RLP-encoded data to mark several data structuring instead of lengths, etc.
    uint8 constant STRING_SHORT_START = 0x80;
    uint8 constant STRING_LONG_START  = 0xb8;
    uint8 constant LIST_SHORT_START   = 0xc0;
    uint8 constant LIST_LONG_START    = 0xf8;

    /**
        @dev RLPItem contains a pointer to the data (obtained using assembly add()) and data length
     */
    struct RLPItem {
        uint len;
        uint memPtr;
    }

    /*
    * @dev convert byte array into RLP object
    * @param item RLP encoded bytes
    */
    function toRlpItem(bytes memory item) internal pure returns (RLPItem memory) {
        uint memPtr;
        assembly {
            memPtr := add(item, 0x20)
        }

        return RLPItem(item.length, memPtr);
    }

    /*
    * @dev transaction could be not a purely RLP-encoded bytes, but hold 1st byte
    *   as a transaction type prefix (prefixes in use are 0x01 Berlin-type transaction, having
        access list in its data, and 0x02 London-type transaction, that has modified gas price parameters)
    */
    function toRlpItemStripTxPrefix(bytes memory item) internal pure returns (RLPItem memory) {
        uint memPtr;
        assembly {
            memPtr := add(item, 0x21) // skip 32 bytes length and 1 byte tx prefix
        }

        return RLPItem(item.length - 1, memPtr);
    }

    /*
     * @param the RLP item.
     * @return (memPtr, len) pair: location of the item's payload in memory.
     */
    function payloadLocation(RLPItem memory item) internal pure returns (uint memPtr, uint len) {
        uint offset = _payloadOffset(item.memPtr);
        memPtr = item.memPtr + offset;
        len = item.len - offset; // data length
    }

    /*
    * @param the RLP item containing the encoded list.
    *   used to decode structures from RLP-encoded data, such as RLP-encoded transaction
    */
    function toList(RLPItem memory item) internal pure returns (RLPItem[] memory) {
        require(isList(item));

        uint items = numItems(item);
        RLPItem[] memory result = new RLPItem[](items);

        uint memPtr = item.memPtr + _payloadOffset(item.memPtr);
        uint dataLen;
        for (uint i = 0; i < items; i++) {
            dataLen = _itemLength(memPtr);
            result[i] = RLPItem(dataLen, memPtr); 
            memPtr = memPtr + dataLen;
        }

        return result;
    }

    /**
        @dev check that RLP item is a list
        @return indicator whether encoded payload is a list. negate this function call for isData.
     */ 
    function isList(RLPItem memory item) internal pure returns (bool) {
        if (item.len == 0) return false;

        uint8 byte0;
        uint memPtr = item.memPtr;
        assembly {
            byte0 := byte(0, mload(memPtr))
        }

        if (byte0 < LIST_SHORT_START)
            return false;
        return true;
    }

    /*
     * @dev A cheaper version of keccak256(toRlpBytes(item)) that avoids copying memory.
     * @return keccak256 hash of RLP encoded bytes.
     */
    function rlpBytesKeccak256(RLPItem memory item) internal pure returns (bytes32) {
        uint256 ptr = item.memPtr;
        uint256 len = item.len;
        bytes32 result;
        assembly {
            result := keccak256(ptr, len)
        }
        return result;
    }

    /*
      RLPItem conversions into data types
    */

    // @returns raw rlp encoding in bytes
    function toRlpBytes(RLPItem memory item) internal pure returns (bytes memory) {
        bytes memory result = new bytes(item.len);
        if (result.length == 0) return result;
        
        uint ptr;
        assembly {
            ptr := add(0x20, result)
        }

        ByteUtil.memcpy(item.memPtr, ptr, item.len);
        return result;
    }

    /**
        @dev convert RLP item to 20-byte address
     */
    function toAddress(RLPItem memory item) internal pure returns (address) {
        // 1 byte for the length prefix
        require(item.len == 21);

        // newer solidity requires explicit truncation
        return address(uint160(toUint(item)));
    }

    /**
        @dev convert RLP item to uint (in RLP uint is tightly packed)
     */
    function toUint(RLPItem memory item) internal pure returns (uint result) {
        require(item.len > 0 && item.len <= 33);

        (uint memPtr, uint len) = payloadLocation(item);

        assembly {
            result := mload(memPtr)

            // shift to the correct location if neccesary
            if lt(len, 32) {
                result := div(result, exp(256, sub(32, len)))
            }
        }
    }

    /**
        @dev convert RLP item to a byte array, uses memory copying
     */
    function toBytes(RLPItem memory item) internal pure returns (bytes memory) {
        require(item.len > 0);

        (uint memPtr, uint len) = payloadLocation(item);
        bytes memory result = new bytes(len);

        uint destPtr;
        assembly {
            destPtr := add(0x20, result)
        }

        ByteUtil.memcpy(memPtr, destPtr, len);
        return result;
    }

    /*
    * Private Helpers
    */

    /**
        @dev count item count of RLP-encoded list
        @return count number of payload items inside an encoded list.
      */
    function numItems(RLPItem memory item) private pure returns (uint count) {
        if (item.len == 0) return 0;

        uint currPtr = item.memPtr + _payloadOffset(item.memPtr);
        uint endPtr = item.memPtr + item.len;
        while (currPtr < endPtr) {
            // skip over an item using its length
            currPtr = currPtr + _itemLength(currPtr);
            count++;
        }
    }

    /**
      @dev in RLP-encoded data, length are encoded using several boundary values to keep
        data size smaller for most circumstances. This method decodes RLP-encoded length information
        that usually preceeds the actual data that follows
      @return itemLen entire rlp item byte length
    */
    function _itemLength(uint memPtr) private pure returns (uint itemLen) {
        uint byte0;
        assembly {
            byte0 := byte(0, mload(memPtr))
        }

        if (byte0 < STRING_SHORT_START)
            itemLen = 1;

        else if (byte0 < STRING_LONG_START)
            itemLen = byte0 - STRING_SHORT_START + 1;

        else if (byte0 < LIST_SHORT_START) {
            assembly {
                let byteLen := sub(byte0, 0xb7) // # of bytes the actual length is
                memPtr := add(memPtr, 1) // skip over the first byte
                
                /* 32 byte word size */
                let dataLen := div(mload(memPtr), exp(256, sub(32, byteLen))) // right shifting to get the len
                itemLen := add(dataLen, add(byteLen, 1))
            }
        }

        else if (byte0 < LIST_LONG_START) {
            itemLen = byte0 - LIST_SHORT_START + 1;
        } 

        else {
            assembly {
                let byteLen := sub(byte0, 0xf7)
                memPtr := add(memPtr, 1)

                let dataLen := div(mload(memPtr), exp(256, sub(32, byteLen))) // right shifting to the correct length
                itemLen := add(dataLen, add(byteLen, 1))
            }
        }
    }

    /**
        @dev RLP item payload location can differ whether it's an actual singular value, string, or a list
        @return number of bytes until the data
    */
    function _payloadOffset(uint memPtr) private pure returns (uint) {
        uint byte0;
        assembly {
            byte0 := byte(0, mload(memPtr))
        }

        if (byte0 < STRING_SHORT_START) 
            return 0;
        else if (byte0 < STRING_LONG_START || (byte0 >= LIST_SHORT_START && byte0 < LIST_LONG_START))
            return 1;
        else if (byte0 < LIST_SHORT_START)  // being explicit
            return byte0 - (STRING_LONG_START - 1) + 1;
        else
            return byte0 - (LIST_LONG_START - 1) + 1;
    }
}
