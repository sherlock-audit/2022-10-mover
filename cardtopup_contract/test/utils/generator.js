const { BlockHeader } = require('@ethereumjs/block');
const { Common } = require('@ethereumjs/common');
const { RLP } = require ('@ethereumjs/rlp');
const { AccessListEIP2930Transaction, FeeMarketEIP1559Transaction, Transaction } = require('@ethereumjs/tx');
const { Address, bigIntToUnpaddedBuffer } = require('@ethereumjs/util');
const { BaseTrie } = require('merkle-patricia-tree');


const { getNibbles, consumeCommonPrefix } = require('./mpt.js');
const { bigIntToDecimalString, bigIntToHexString, uintBufferToHex } = require('./parsing.js');

class ProofGenerator {
  async calcTransactionProof(blockNumber, txIndex) {
   
    const commonCfg = new Common({ chain: "develop", customChains: [
      {
        "name": "develop",
        "chainId": 1337,
        "networkId": 1337,
        "defaultHardfork": "istanbul",
        "consensus": {
          "type": "poa",
          "algorithm": "clique",
          "clique": {
            "period": 15,
            "epoch": 30000
          }
        },
        "comment": "truffle test network",
        "url": "https://localhost",
        "genesis": {
          "timestamp": "0x5c51a607",
          "gasLimit": 10485760,
          "difficulty": 1,
          "nonce": "0x0000000000000000",
          "extraData": "0x22466c6578692069732061207468696e6722202d204166726900000000000000e0a2bd4258d2768837baa26a28fe71dc079f84c70000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        },
        "hardforks": [
          {
            "name": "chainstart",
            "block": 0,
            "forkHash": "0xa3f5ab08"
          },
          {
            "name": "homestead",
            "block": 0,
            "forkHash": "0xa3f5ab08"
          },
          {
            "name": "tangerineWhistle",
            "block": 0,
            "forkHash": "0xa3f5ab08"
          },
          {
            "name": "spuriousDragon",
            "block": 0,
            "forkHash": "0xa3f5ab08"
          },
          {
            "name": "byzantium",
            "block": 0,
            "forkHash": "0xa3f5ab08"
          },
          {
            "name": "constantinople",
            "block": 0,
            "forkHash": "0xa3f5ab08"
          },
          {
            "name": "petersburg",
            "block": 0,
            "forkHash": "0xa3f5ab08"
          },
          {
            "name": "istanbul",
            "block": 0,
            "forkHash": "0xc25efa5c"
          },
          {
            "name": "berlin",
            "block": null,
            "forkHash": "0x757a1c47"
          },
          {
            "name": "london",
            "block": null,
            "forkHash": "0xb8c6299d"
          },
          {
            "name": "merge",
            "block": null,
            "forkHash": "0xb8c6299d"
          },
          {
            "name": "mergeForkIdTransition",
            "block": null,
            "forkHash": null
          },
          {
            "name": "shanghai",
            "block": null,
            "forkHash": null
          }
        ],
        "bootstrapNodes": [],
        "dnsNetworks": []
      }
    ]});

    const blockData = await web3.eth.getBlock(blockNumber, true);

    const header = BlockHeader.fromHeaderData(
      {
        difficulty: BigInt(blockData.difficulty),
        gasLimit: blockData.gasLimit,
        number: blockData.number,
        timestamp: blockData.timestamp,
        coinbase: blockData.miner,
        parentHash: blockData.parentHash,
        uncleHash: blockData.sha3Uncles,
        stateRoot: blockData.stateRoot,
        transactionsTrie: web3.utils.hexToBytes(
          blockData.transactionsRoot
        ),
        receiptTrie: web3.utils.hexToBytes(
          blockData.receiptsRoot
        ),
        logsBloom: blockData.logsBloom,
        gasUsed: blockData.gasUsed,
        extraData: blockData.extraData,
        mixHash: blockData.mixHash,
        nonce: blockData.nonce,
        baseFeePerGas: undefined /* blockData.baseFeePerGas for local truffle */
      },
      { common: commonCfg, skipConsensusFormatValidation: true }
    );

    const trie = new BaseTrie();
    for (const t of blockData.transactions) {
      const key = RLP.encode(t.transactionIndex);
      const val = this.rlpTransaction(t, commonCfg);
      const hexVal = uintBufferToHex(val);
      await trie.put(Buffer.from(key), Buffer.from(hexVal, 'hex'));
    }

    const rootHash = trie.root;

    if (Buffer.compare(header.transactionsTrie, rootHash) !== 0) {
      throw new Error('Tx trie root hash is wrong');
    }

    const stack = await this.getTrieStackForTx(trie, txIndex);
    const proofType = 1;
    const proofBlob = RLP.encode([
      proofType,
      header.raw(),
      txIndex,
      stack.map((n) => n.raw())
    ]);

    return proofBlob;
  }

  async getTrieStackForTx(trie, txIndex) {
    const keyNibbles = getNibbles(RLP.encode(txIndex)).flat();

    for (const nibble of keyNibbles) {
      if (nibble < 0 || nibble > 16) {
        throw new Error('keyNibbles has wrong elements');
      }
    }

    const stackIndexes = [];
    const stack = [];

    const aux = async (nodeHash, keyNibbles) => {
      if (nodeHash === null) {
        return;
      }
      const node = await trie.lookupNode(nodeHash);
      if (node === null) {
        return;
      } else if (node.constructor.name == 'BranchNode') {
        if (keyNibbles.length > 0) {
          const i = keyNibbles[0];
          stackIndexes.push(i);
          stack.push(node);
          await aux(node.getBranch(i), keyNibbles.slice(1));
        } else {
          const i = 16;
          stackIndexes.push(i);
          stack.push(node);
        }
        return;
      } else if (node.constructor.name == 'ExtensionNode' || node.constructor.name == 'LeafNode') {
        const key = node.key;

        const keyData = consumeCommonPrefix(key, keyNibbles);
        if (keyData.leftReminder.length === 0) {
          stackIndexes.push(1);
          stack.push(node);
          if (node.constructor.name == 'ExtensionNode') {
            await aux(node.value, keyData.rightReminder);
          }
        } else {
          stackIndexes.push(0xff);
          stack.push(node);
        }
        return;
      } else {
        throw new Error('Unknown node type');
      }
    };

    await aux(trie.root, keyNibbles);

    return stack;
  }

  rlpTransaction(txData, common) {
    let txType = txData.type;

    let response;
    let transaction;

    if (txType === 1) {
      const accessList = this.parseAssets(txData);

      const t = AccessListEIP2930Transaction.fromTxData(
        {
          nonce: txData.nonce,
          gasPrice: parseInt(txData.gasPrice),
          gasLimit: txData.gas,
          to: txData.to ?? '',
          value: bigIntToHexString(BigInt(txData.value)),
          data: web3.utils.hexToBytes(txData.input),
          v: bigIntToHexString(BigInt(txData.v)),
          r: bigIntToHexString(BigInt(txData.r)),
          s: bigIntToHexString(BigInt(txData.s)),
          accessList: accessList
        },
        { common: common }
      );
      transaction = t;

      response = RLP.encode([
        bigIntToUnpaddedBuffer(t.chainId),
        bigIntToUnpaddedBuffer(t.nonce),
        bigIntToUnpaddedBuffer(t.gasPrice),
        bigIntToUnpaddedBuffer(t.gasLimit),
        t.to !== undefined ? t.to.buf : Buffer.from([]),
        bigIntToUnpaddedBuffer(t.value),
        t.data,
        t.accessList,
        t.v !== undefined ? bigIntToUnpaddedBuffer(t.v) : Buffer.from([]),
        t.r !== undefined ? bigIntToUnpaddedBuffer(t.r) : Buffer.from([]),
        t.s !== undefined ? bigIntToUnpaddedBuffer(t.s) : Buffer.from([])
      ]);
      response = new Uint8Array([1, ...response]);
    } else if (txType === 2) {
      const accessList = this.parseAssets(txData);

      const t = FeeMarketEIP1559Transaction.fromTxData(
        {
          nonce: txData.nonce,
          maxPriorityFeePerGas: parseInt(txData.maxPriorityFeePerGas),
          maxFeePerGas: parseInt(txData.maxFeePerGas),
          gasLimit: txData.gas,
          to: txData.to ?? '',
          value: bigIntToHexString(BigInt(txData.value)),
          data: web3.utils.hexToBytes(txData.input),
          v: bigIntToHexString(BigInt(txData.v)),
          r: bigIntToHexString(BigInt(txData.r)),
          s: bigIntToHexString(BigInt(txData.s)),
          accessList: accessList
        },
        { common: common }
      );
      transaction = t;

      response = RLP.encode([
        bigIntToUnpaddedBuffer(t.chainId),
        bigIntToUnpaddedBuffer(t.nonce),
        bigIntToUnpaddedBuffer(t.maxPriorityFeePerGas),
        bigIntToUnpaddedBuffer(t.maxFeePerGas),
        bigIntToUnpaddedBuffer(t.gasLimit),
        t.to !== undefined ? t.to.buf : Buffer.from([]),
        bigIntToUnpaddedBuffer(t.value),
        t.data,
        t.accessList,
        t.v !== undefined ? bigIntToUnpaddedBuffer(t.v) : Buffer.from([]),
        t.r !== undefined ? bigIntToUnpaddedBuffer(t.r) : Buffer.from([]),
        t.s !== undefined ? bigIntToUnpaddedBuffer(t.s) : Buffer.from([])
      ]);
      response = new Uint8Array([2, ...response]);
    } else {
      // Legacy transaction

      const t = Transaction.fromTxData(
        {
          nonce: txData.nonce,
          gasPrice: parseInt(txData.gasPrice),
          gasLimit: txData.gas,
          to: txData.to ?? '',
          value: bigIntToDecimalString(BigInt(txData.value)),
          data: web3.utils.hexToBytes(txData.input),
          v: bigIntToHexString(BigInt(txData.v)),
          r: bigIntToHexString(BigInt(txData.r)),
          s: bigIntToHexString(BigInt(txData.s))
        },
        { common: common }
      );
      transaction = t;

      response = RLP.encode([
        bigIntToUnpaddedBuffer(t.nonce),
        bigIntToUnpaddedBuffer(t.gasPrice),
        bigIntToUnpaddedBuffer(t.gasLimit),
        t.to !== undefined ? t.to.buf : Buffer.from([]),
        bigIntToUnpaddedBuffer(t.value),
        t.data,
        t.v !== undefined ? bigIntToUnpaddedBuffer(t.v) : Buffer.from([]),
        t.r !== undefined ? bigIntToUnpaddedBuffer(t.r) : Buffer.from([]),
        t.s !== undefined ? bigIntToUnpaddedBuffer(t.s) : Buffer.from([])
      ]);
    }

    const calculatedHash = `0x${transaction.hash().toString('hex')}`;

    if (calculatedHash !== txData.hash) {
      throw new Error('Tx hash is wrong');
    }

    return response;
  }

  parseAssets(txData) {
    const accessList = [];
    if ('accessList' in txData && txData.accessList !== undefined) {
      for (const accAccess of txData.accessList) {
        const stKeys = [];
        for (const stKey of accAccess.storageKeys) {
          stKeys.push(stKey);
          const accItem = {
            address: Address.fromString(accAccess.address).toString(),
            storageKeys: stKeys
          };
          accessList.push(accItem);
        }
      }
    }
    return accessList;
  }
}

module.exports = { ProofGenerator };
