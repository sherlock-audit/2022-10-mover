import argparse
import json
import sys
from typing import List, Tuple, Iterable

from ethereum import (
    block,
    messages,
    transactions,
    utils
)

from eth.vm.forks.london.blocks import (
    LondonBlockHeader
)

from eth.vm.forks.berlin.transactions import (
    AccessListPayloadDecoder,
    AccountAccesses,
    AccessListTransaction,
    TypedTransaction,
)

from eth.vm.forks.berlin.constants import (
    ACCESS_LIST_TRANSACTION_TYPE
)

from rlp.sedes import (
    CountableList,
    BigEndianInt
)

from eth_utils.address import (
    to_normalized_address,
    to_canonical_address,
)

from eth.rlp.sedes import address

from eth.typing import (
    Address
)

from typing import (
    Sequence,
    Tuple
)

from eth.vm.forks.london.transactions import (
    LondonTransactionBuilder,
    LondonTypedTransaction,
    DynamicFeeTransaction
)

from eth.vm.forks.london.constants import (
    DYNAMIC_FEE_TRANSACTION_TYPE,
)

from eth.rlp.sedes import (
    hash32
)

from eth_typing import (
    Hash32
)


import pprint
import requests
import rlp

from rlp.sedes import (
    big_endian_int
)



from trie import HexaryTrie
from trie.constants import (
    BLANK_NODE,
    BLANK_NODE_HASH,
    NODE_TYPE_BLANK,
    NODE_TYPE_LEAF,
    NODE_TYPE_EXTENSION,
    NODE_TYPE_BRANCH,
    BLANK_HASH,
)
from trie.utils.nodes import *
from trie.utils.nibbles import encode_nibbles, decode_nibbles, bytes_to_nibbles
import math

MODULE_DEBUG = False

def rec_hex(x):
    if isinstance(x, list):
        return [rec_hex(elem) for elem in x]
    else:
        return utils.encode_hex(x)

def rec_bin(x):
    if isinstance(x, list):
        return [rec_bin(elem) for elem in x]
    elif isinstance(x, int):
        return x
    elif isinstance(x, str):
        if x.startswith("0x"):
            if len(x) != 2:
                return utils.decode_hex(x[2:])
            else:
                return 0
        else:
            return utils.decode_hex(x)
    elif x is None:
        return 0

def normalize_bytes(hash):
    if isinstance(hash, str):
        if hash.startswith("0x"):
            hash = hash[2:]
        if len(hash) % 2 != 0:
            hash = '0' + hash
        return utils.decode_hex(hash)
    elif isinstance(hash, int):
        return hash.to_bytes(length=(math.ceil(hash.bit_length() / 8)),
                             byteorder="big",
                             signed=False)
    else:
        return bytes(hash)

def str2bool(v):
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def get_args():
    parser = argparse.ArgumentParser(
        description="Patricia Merkle Trie Proof Generating Tool",
        formatter_class=argparse.RawTextHelpFormatter)
    # TODO add stuff around adding a block header and then generating proofs of
    # inclusion / exclusion etc etc etc
    blockInfoGroup = parser.add_mutually_exclusive_group(required=True)
    blockInfoGroup.add_argument('-n', '--block-number',
                        default="",
                        help="Block number that transaction exists in")
    blockInfoGroup.add_argument('-b', '--block-hash',
                        default="",
                        help="Block hash that transaction exists in")
    parser.add_argument('-tr', '--transaction_receipt_mode', required=False,
                        type=str2bool, default="False",
                        help="If the proof should be for a transaction receipt")
    parser.add_argument('-i', '--transaction_index', required=True, type=int,
                        default="",
                        help="Zero-based index of the transaction in the "
                        "block (e.g. the third transaction in the block is at "
                        "index 2)")
    parser.add_argument('-r', '--rpc', required=True,
                        default="",
                        help="URL of web3 rpc node. (e.g. "
                        "http://localhost:8545)")
    parser.add_argument('-v', '--verbose', required=False, action='store_true',
                        help="Print verbose output")
    return parser.parse_args()

def block_header(block_dict: dict):
    #Hash32(normalize_bytes(block_dict["sha3Uncles"])),
    #Hash32(32 * b'\x00'),
    b = LondonBlockHeader(
        big_endian_int.deserialize(normalize_bytes(block_dict['difficulty'])),
        big_endian_int.deserialize(normalize_bytes(block_dict['number'])),
        big_endian_int.deserialize(normalize_bytes(block_dict['gasLimit'])),
        big_endian_int.deserialize(normalize_bytes(block_dict['timestamp'])),
        utils.normalize_address(block_dict["miner"]),
        normalize_bytes(block_dict["parentHash"]),
        Hash32(normalize_bytes(block_dict["sha3Uncles"])),
        normalize_bytes(block_dict["stateRoot"]),
        normalize_bytes(block_dict["transactionsRoot"]),
        normalize_bytes(block_dict["receiptsRoot"]),
        utils.bytes_to_int(normalize_bytes(block_dict["logsBloom"])),
        big_endian_int.deserialize(normalize_bytes(block_dict['gasUsed'])),
        normalize_bytes(block_dict["extraData"]),
        normalize_bytes(block_dict["mixHash"]),
        normalize_bytes(block_dict["nonce"]),
        big_endian_int.deserialize(normalize_bytes(block_dict["baseFeePerGas"])),
    )
    #print((normalize_bytes(block_dict["parentHash"])))
    if normalize_bytes(block_dict["hash"]) != b.hash:
        raise ValueError(
            """Blockhash does not match.
            Received invalid block header? {} vs {}""".format(
                str(normalize_bytes(block_dict["hash"])),
                str(b.hash)))
    return b

def rlp_transaction(tx_dict: dict):

    #print("----------------------------------------------")

    t = 0

    if utils.parse_as_int(tx_dict['type']) == 1:
        #print('Berlin tx')
        #print(tx_dict)
        #print('Preparing access list')
        accessList = [] #Sequence[Tuple[Address, Sequence[int]]] #[] #CountableList(AccountAccesses)
        if 'accessList' in tx_dict:
            for accAccess in tx_dict['accessList']:
                #print("""Found access list record {}""".format(accAccess))
                stKeys = [] #Sequence[int] #CountableList(BigEndianInt(32))
                for stKey in accAccess['storageKeys']:
                    #addr = BigEndianInt(32)
                    #addr.deserialize
                    stKeys.append(utils.parse_as_int(stKey))
                accItem = (to_canonical_address(accAccess['address']), stKeys) #AccountAccesses(accAccess['address'], stKeys)
                accessList.append(accItem)
            #accessList.deserialize(tx_dict['accessList'])

        t = TypedTransaction(ACCESS_LIST_TRANSACTION_TYPE, AccessListTransaction(
            utils.parse_as_int('137'),
            #chainId
            utils.parse_as_int(tx_dict['nonce']),
            #utils.parse_as_int(tx_dict['gasPrice']),
            #utils.parse_as_int(tx_dict['maxPriorityFeePerGas']),
            utils.parse_as_int(tx_dict['gasPrice']),
            utils.parse_as_int(tx_dict['gas']),
            normalize_bytes(tx_dict['to'] or ''),
            utils.parse_as_int(tx_dict['value']),
            utils.decode_hex(tx_dict['input']),
            accessList,
            #AccessListPayloadDecoder.decode(tx_dict['accessList']),
            utils.parse_as_int(tx_dict['v']),
            utils.bytes_to_int(normalize_bytes(tx_dict['r'])),
            utils.bytes_to_int(normalize_bytes(tx_dict['s'])),
        ))

        a = b'\x01'
        #return rlp.encode(a + rlp.encode(t))
        #return rlp.encode(b"".join([a, rlp.encode(t)])) #rlp.encode(a + rlp.encode(t))
        #return rlp.encode(t)
        return b"".join([a, rlp.encode(t)])

    if utils.parse_as_int(tx_dict['type']) == 2:
        print('London tx')
        print(tx_dict)
        #print('Preparing access list')
        accessList = [] #Sequence[Tuple[Address, Sequence[int]]] #[] #CountableList(AccountAccesses)
        if 'accessList' in tx_dict:
            for accAccess in tx_dict['accessList']:
                #print("""Found access list record {}""".format(accAccess))
                stKeys = [] #Sequence[int] #CountableList(BigEndianInt(32))
                for stKey in accAccess['storageKeys']:
                    #addr = BigEndianInt(32)
                    #addr.deserialize
                    stKeys.append(utils.parse_as_int(stKey))
                accItem = (to_canonical_address(accAccess['address']), stKeys) #AccountAccesses(accAccess['address'], stKeys)
                accessList.append(accItem)
            #accessList.deserialize(tx_dict['accessList'])

        t = LondonTypedTransaction(DYNAMIC_FEE_TRANSACTION_TYPE, DynamicFeeTransaction(
            utils.parse_as_int('137'),
            #chainId
            utils.parse_as_int(tx_dict['nonce']),
            #utils.parse_as_int(tx_dict['gasPrice']),
            utils.parse_as_int(tx_dict['maxPriorityFeePerGas']),
            utils.parse_as_int(tx_dict['maxFeePerGas']),
            utils.parse_as_int(tx_dict['gas']),
            normalize_bytes(tx_dict['to'] or ''),
            utils.parse_as_int(tx_dict['value']),
            utils.decode_hex(tx_dict['input']),
            accessList,
            #AccessListPayloadDecoder.decode(tx_dict['accessList']),
            utils.parse_as_int(tx_dict['v']),
            utils.bytes_to_int(normalize_bytes(tx_dict['r'])),
            utils.bytes_to_int(normalize_bytes(tx_dict['s'])),
        ))

        a = b'\x02'
        print(rlp.encode(t).hex())
        #print((b"".join([a, rlp.encode(t)])).hex())
        #return rlp.encode(b"".join([a, rlp.encode(t)])) #rlp.encode(a + rlp.encode(t))
        #return b"".join([a, rlp.encode(t)[:]])
        print("""STUFF: {} {}""".format(rlp.encode(t)[3], rlp.encode(t)[3] != 2))
        if rlp.encode(t)[3] != 2:
            return b"".join([a, rlp.encode(t)[3:]])

        return rlp.encode(t)[3:]

    else:
        #print('Legacy tx')
        t = transactions.Transaction(
            utils.parse_as_int(tx_dict['nonce']),
            utils.parse_as_int(tx_dict['gasPrice']),
            utils.parse_as_int(tx_dict['gas']),
            normalize_bytes(tx_dict['to'] or ''),
            utils.parse_as_int(tx_dict['value']),
            utils.decode_hex(tx_dict['input']),
            utils.parse_as_int(tx_dict['v']),
            utils.bytes_to_int(normalize_bytes(tx_dict['r'])),
            utils.bytes_to_int(normalize_bytes(tx_dict['s'])),
        )


    #for item in tx_dict:
    #    print("""{} = {}""".format(item, tx_dict[item]))

    if normalize_bytes(tx_dict['hash']) != t.hash:
        raise ValueError("""Tx hash does not match. Received invalid transaction?
        hashes:         {} {}
        nonce:          {}
        gasPrice:       {}
        gas:            {}
        to:             {}
        value:          {}
        input:          {}
        v:              {}
        r:              {}
        s:              {}
        """.format(
            tx_dict['hash'], t.hash,
            utils.parse_as_int(tx_dict['nonce']),
            utils.parse_as_int(tx_dict['gasPrice']),
            utils.parse_as_int(tx_dict['gas']),
            normalize_bytes(tx_dict['to'] or ''),
            utils.parse_as_int(tx_dict['value']),
            utils.decode_hex(tx_dict['input']),
            utils.parse_as_int(tx_dict['v']),
            utils.bytes_to_int(normalize_bytes(tx_dict['r'])),
            utils.bytes_to_int(normalize_bytes(tx_dict['s'])),
        ))

    return rlp.encode(t)

    #print(rlp.encode(t))


def generate_proof(mpt, mpt_key_nibbles: bytes):
    if not all(0 <= nibble < 16 for nibble in mpt_key_nibbles):
        raise ValueError("mpt_key_nibbles has non-nibble elements {}".format(str(mpt_key_nibbles)))
    EMPTY = 128
    stack_indexes = []
    stack = []

    def aux(node_hash, mpt_key_nibbles):
        nonlocal stack_indexes
        nonlocal stack

        node = mpt.get_node(node_hash)
        if get_node_type(node) == NODE_TYPE_BLANK:
            if MODULE_DEBUG:
                print("Hit an empty node, returning")
            return
        elif get_node_type(node) == NODE_TYPE_BRANCH:
            if MODULE_DEBUG:
                print("Hit a branch node")
            if mpt_key_nibbles:
                i = mpt_key_nibbles[0]
                stack_indexes.append(i)
                stack.append(node)
                aux(node[i], mpt_key_nibbles[1:])
            else:
                i = 16
                stack_indexes.append(i)
                stack.append(node)
        elif get_node_type(node) in [NODE_TYPE_EXTENSION, NODE_TYPE_LEAF]:
            if MODULE_DEBUG:
                print("Hit an extension/branch node")
            key = extract_key(node)
            prefix, key_remainder, mpt_key_nibbles_remainder = \
                    consume_common_prefix(key, mpt_key_nibbles)
            if not key_remainder:
                if MODULE_DEBUG:
                    print("Non-divergent leaf/extension")
                stack_indexes.append(1)
                stack.append(node)
                if get_node_type(node) == NODE_TYPE_EXTENSION:
                    aux(node[1], mpt_key_nibbles_remainder)
            else:
                if MODULE_DEBUG:
                    print("Divergent leaf/extension")
                stack_indexes.append(0xff)
                stack.append(node)
        else:
            raise ValueError("Unknown node type: {}".format(
                get_node_type(node)))


    root_node = mpt.get_node(mpt.root_hash)
    if get_node_type(root_node) == NODE_TYPE_BLANK:
        if MODULE_DEBUG:
            print("Blank root node")
    else:
        aux(mpt.root_hash, mpt_key_nibbles)

    if MODULE_DEBUG:
        print('key nibbles: ', mpt_key_nibbles)
        print('Stack:       ', rec_hex(stack))
        print('StackIndexes:', stack_indexes)

    return stack

def construct_proof_from_mpt(mpt, header, tx_index, proof_type):
    mpt_key_nibbles = bytes_to_nibbles(rlp.encode(tx_index))
    stack = generate_proof(mpt, mpt_key_nibbles)

    proof_blob = rlp.encode([
        proof_type,
        header,
        tx_index,
        stack,
    ])
    return proof_blob

def generate_proof_blob(block_dict, tx_index):
    header = block_header(block_dict)

    mpt = HexaryTrie(db={})

    #mpt.set(rlp.encode(1), rlp.encode(2))
    #mpt.set(rlp.encode(3), rlp.encode(4))

    #print("""ROOT HASH={}""".format(mpt.root_hash.hex()))


    for tx_dict in block_dict["transactions"]:
        #if utils.parse_as_int(tx_dict['transactionIndex']) == 0:
        #    continue
        #if utils.parse_as_int(tx_dict['transactionIndex']) == 21:
        #    break
        key = rlp.encode(utils.parse_as_int(tx_dict['transactionIndex']))
        valrlp = rlp_transaction(tx_dict)
        #print("""key {} rlp {}""".format(tx_dict['transactionIndex'], key.hex()))
        #print("""rlp {}""".format(utils.parse_as_int(tx_dict['transactionIndex']), tx_dict['hash'], rlp_transaction(tx_dict).hex()))
        print("""rlp {}""".format(valrlp.hex()))
        mpt.set(key, valrlp)

    print("""ROOT HASH={}""".format(mpt.root_hash.hex()))

    if mpt.root_hash != normalize_bytes(block_dict['transactionsRoot']):
        raise ValueError(
            "Tx trie root hash does not match. Calculated: {} Sent: {}"
            .format(mpt.root_hash.hex(),
                    normalize_bytes(block_dict['transactionsRoot']).hex()))

    return construct_proof_from_mpt(mpt, header, tx_index, 1)


def decode_int_from_hex(x):
    return utils.decode_int(utils.decode_hex(x).lstrip(b"\x00"))

def get_receipt_from_jsonrpc(response):
    if MODULE_DEBUG:
        print(response)
    assert response['jsonrpc'] == '2.0'
    assert 'id' in response
    assert 'result' in response
    receipt = response['result']
    logs = []
    for log in receipt['logs']:
        topics = [decode_int_from_hex(x) for x in log['topics']]
        logs.append(messages.Log(
            address = utils.normalize_address(log['address']),
            topics = topics,
            data = utils.decode_hex(log['data'])))
    # pre Byzantium returns a root
    if 'root' in receipt:
        return messages.Receipt(
            state_root = normalize_bytes(receipt['root']),
            gas_used = utils.parse_as_int(receipt['cumulativeGasUsed']),
            bloom = utils.parse_as_int(receipt['logsBloom']),
            logs = logs)
    receipt = messages.Receipt(
        state_root = (b'\x01' if receipt['status'] else b''),
        gas_used = utils.parse_as_int(receipt['cumulativeGasUsed']),
        bloom = utils.parse_as_int(receipt['logsBloom']),
        logs = logs)
    if MODULE_DEBUG:
        print("Rlp encoded receipt:")
        print(rec_hex(rlp.encode(receipt)))
    return receipt

def get_receipt(url, transaction_hash):
    request = {
        "jsonrpc":"2.0",
        "method":"eth_getTransactionReceipt",
        "params":[transaction_hash],
        "id":1,
    }
    if MODULE_DEBUG:
        print(request)
    r = requests.post(url, json=request)
    r.raise_for_status()
    return get_receipt_from_jsonrpc(r.json())

def generate_proof_blob_receipt(block_dict, tx_index, url):
    header = block_header(block_dict)

    mpt = HexaryTrie(db={})
    for tx_dict in block_dict["transactions"]:
        key = rlp.encode(utils.parse_as_int(tx_dict['transactionIndex']))
        receipt = get_receipt(url, tx_dict['hash'])
        mpt.set(key, rlp.encode(receipt))

    if mpt.root_hash != normalize_bytes(block_dict['receiptsRoot']):
        if MODULE_DEBUG:
            print("mpt.root_hash " + str(utils.encode_hex(mpt.root_hash)))
            print("receiptRoot " +
                  str(normalize_bytes(utils.encode_hex(block_dict['receiptsRoot']))))
        raise ValueError("Block receiptRoot hash does not match.")

    return construct_proof_from_mpt(mpt, header, tx_index, 2)

def generate_proof_blob_from_jsonrpc_response(response, tx_index,
                                              url="", receipt_mode=False):
    if MODULE_DEBUG:
        print(response)
    assert response['jsonrpc'] == '2.0'
    assert 'id' in response
    assert 'result' in response
    if receipt_mode:
        return generate_proof_blob_receipt(response['result'], tx_index, url)
    return generate_proof_blob(response['result'], tx_index)


def generate_proof_blob_from_jsonrpc_using_hash(url, block_hash,
                                                tx_index, receipt_mode=False):
    request = {
        "jsonrpc":"2.0",
        "method":"eth_getBlockByHash",
        "params":['0x' + utils.encode_hex(block_hash), True],
        "id":1,
    }
    if MODULE_DEBUG:
        print(request)
    r = requests.post(url, json=request)
    r.raise_for_status()
    return generate_proof_blob_from_jsonrpc_response(r.json(), tx_index,
                                                     url, receipt_mode)

def generate_proof_blob_from_jsonrpc_using_number(url, block_number,
                                                  tx_index, receipt_mode=False):
    request = {
        "jsonrpc":"2.0",
        "method":"eth_getBlockByNumber",
        "params":[str(hex(block_number)), True],
        "id":1,
    }
    if MODULE_DEBUG:
        print(request)
    r = requests.post(url, json=request)
    r.raise_for_status()
    return generate_proof_blob_from_jsonrpc_response(r.json(), tx_index,
                                                     url, receipt_mode)

def main():
    args = get_args()
    if args.verbose:
        global MODULE_DEBUG
        MODULE_DEBUG = True
    if args.block_hash:
        proof_blob = generate_proof_blob_from_jsonrpc_using_hash(
            args.rpc, utils.decode_hex(args.block_hash),
            args.transaction_index, args.transaction_receipt_mode)
    elif args.block_number:
        proof_blob = generate_proof_blob_from_jsonrpc_using_number(
            args.rpc, int(args.block_number),
            args.transaction_index, args.transaction_receipt_mode)
    else:
        print("Either --block-hash or --block-number are required")
        exit(1)

    print("Final Output: ")
    print(rec_hex(proof_blob))
    exit(0)

if __name__ == "__main__":
    main()
