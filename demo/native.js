const {
  addressFromPrivateKey,
  Collector,
  getJoyIDCellDep,
  keccak160,
  keyFromPrivate,
  SigAlg,
  remove0x,
  calcSignedWitnessLock,
} = require('@nervina-labs/joyid-sdk')
const { addressToScript, scriptToHash, bytesToHex } = require('@nervosnetwork/ckb-sdk-utils')
const { JsonRpcProvider } = require('../lib.commonjs/providers')
const { Transaction } = require('../lib.commonjs/transaction/transaction')
const { Signature } = require('../lib.commonjs/crypto/signature')
const { parseEther, parseUnits, formatEther} = require('../lib.commonjs/utils')
const RLP = require('rlp')

const MAIN_PRIVATE_KEY = '0x4271c23380932c74a041b4f56779e5ef60e808a127825875f906260f1f657761'
// const ADDRESS = 'ckt1qrfrwcdnvssswdwpn3s9v8fp87emat306ctjwsm3nmlkjg8qyza2cqgqq9sfrkfah2cj79nyp7e6p283ualq8779rscnjmrj'
const TO_AXON_ADDRESS = '0xCb9112D826471E7DEB7Bc895b1771e5d676a14AF'

const AXON_RPC_RUL = 'http://axon-rpc-url'
const CKB_RPC_URL = 'http://127.0.0.1:8114'

// Calculate the actual occupied space according to the mock tx output cell
const OUTPUT_CAPACITY = BigInt(106) * BigInt(100000000)
// blake2b_hash(AlwaysSuccessScript)(https://github.com/jjyr/ckb-always-success-script/blob/master/c/always_success.c)
const AXON_TYPE_CODE_HASH = "0xe683b04139344768348499c23eb1326d5a52d6db006c0d2fece00a831f3660d7"
// The deployment tx hash of always success script(https://github.com/jjyr/ckb-always-success-script/blob/master/c/always_success.c)
const ALWAYS_SUCCESS_TX_HASH = "0xe3c81d510c2e71c4e259abce3884e80f7563b4088a8100b967278e8f179c92c4"

// blake2b_hash("DummyInputOutpointTxHash")
const AXON_INPUT_OUT_POINT_TX_HASH = "0x224b7960223b7ead6bc6e559925456696b9fc309ca5668e32fc69b4ebe25bb66"

const buildNativeCKBTx = async (lock, axonUnsignedHash) => {
  const output = {
    capacity: `0x${OUTPUT_CAPACITY.toString(16)}`,
    lock: {
      codeHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
      hashType: "data",
      args: "0x",
    },
    type: {
      codeHash: AXON_TYPE_CODE_HASH,
      hashType: 'data1',
      args: axonUnsignedHash,
    },
  }

  const collector = new Collector({
    ckbNodeUrl: CKB_RPC_URL,
    ckbIndexerUrl: CKB_RPC_URL,
  })
  const cells = await collector.getCells(lock)
  if (cells == undefined || cells.length == 0) {
    throw new Error('The from address has no live cells')
  }
  const inputs = [
    {
      previousOutput: {
        txHash: AXON_INPUT_OUT_POINT_TX_HASH,
        index: "0x0",
      },
      since: '0x0',
    },
  ]
  const alwaysSuccessCellDep = {
    outPoint: { txHash: ALWAYS_SUCCESS_TX_HASH, index: '0x0' },
    depType: 'code',
  }
  let rawTx = {
    version: '0x0',
    cellDeps: [getJoyIDCellDep(false), alwaysSuccessCellDep],
    headerDeps: [],
    inputs,
    outputs: [output],
    outputsData: [],
    witnesses: [],
  }
  rawTx.witnesses = rawTx.inputs.map((_, i) => (i > 0 ? '0x' : { lock: '', inputType: '', outputType: '' }))
  const key = keyFromPrivate(MAIN_PRIVATE_KEY, SigAlg.Secp256r1)
  rawTx.witnesses[0].lock = calcSignedWitnessLock(key, rawTx)
  console.log(JSON.stringify(rawTx))
  return rawTx
}

const toBuffer = input => Buffer.from(remove0x(input), 'hex')

const signAxonTxWithMainkey = async (lock, axonTx) => {
  const signedTx = await buildNativeCKBTx(lock, axonTx.unsignedHash)

  /**
   * pub struct CKBTxMockByRef {
      pub cell_deps: Vec<CellDep>,
      pub header_deps: Vec<H256>,
      pub input_lock: CellWithData,
      pub out_point_addr_source: AddressSource,
    }

    pub struct CellWithData {
      pub type_script: Option<Script>,
      pub lock_script: Script,
      pub data: Bytes,
    }

    pub struct Witness {
      pub input_type: Option<Bytes>,
      pub output_type: Option<Bytes>,
      pub lock: Option<Bytes>,
    }
   */
  const sigR = [
    [
      [toBuffer(signedTx.cellDeps[0].outPoint.txHash), parseInt(signedTx.cellDeps[0].outPoint.index, 16), 1], 
      [toBuffer(signedTx.cellDeps[1].outPoint.txHash), parseInt(signedTx.cellDeps[1].outPoint.index, 16), 0],
    ],
    [],
    [[], [toBuffer(lock.codeHash), toBuffer(lock.args), 1], "0x"],
    [0, 0]
  ]
  const rlpSigR = bytesToHex(Buffer.concat([Buffer.from([2]), RLP.encode(sigR)]))
  const sigS = [[[[toBuffer(signedTx.witnesses[0].lock)], [], []]]]
  const rlpSigS = bytesToHex(RLP.encode(sigS))

  axonTx.signature = Signature.fromUnchecked(rlpSigR, rlpSigS, 0)

  return axonTx
}

const transferWithMainkey = async () => {
  const provider = new JsonRpcProvider(AXON_RPC_RUL)

  const address = addressFromPrivateKey(MAIN_PRIVATE_KEY, SigAlg.Secp256r1)
  const lock = addressToScript(address)
  const axonAddress = `0x${keccak160(scriptToHash(lock))}`
  console.log('CKB address', address)
  // 0x9447a236092f194ac774e9aaa5294c87e3ad50fd
  console.log('Axon address', axonAddress)

  const balance = await provider.getBalance(axonAddress)
  console.log("Axon account balance: ", formatEther(balance))

  let axonTx = new Transaction()
  axonTx.from = axonAddress
  axonTx.to = TO_AXON_ADDRESS
  axonTx.value = parseEther('1.0')
  axonTx.chainId = 2022
  axonTx.type = 0
  axonTx.from = axonAddress
  axonTx.gasLimit = 21000
  axonTx.gasPrice = parseUnits("0.14", "gwei");

  const txCount = await provider.getTransactionCount(axonAddress)
  axonTx.nonce = txCount

  axonTx = await signAxonTxWithMainkey(lock, axonTx)

  const ret = await provider.send('eth_sendRawTransaction', [axonTx.serialized])

  console.log("Transfer axon with mainkey unlock: ", JSON.stringify(ret))
}

transferWithMainkey()
