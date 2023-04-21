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
// ckt1qrfrwcdnvssswdwpn3s9v8fp87emat306ctjwsm3nmlkjg8qyza2cqgqq9sfrkfah2cj79nyp7e6p283ualq8779r8bcvscnjmrj
const MAIN_PRIVATE_KEY2 = '0xc5a991867f2406bfe6d17028bcc09492b4959ec55ef5812e5f5cf12b3529f7af'
// ckt1qrfrwcdnvssswdwpn3s9v8fp87emat306ctjwsm3nmlkjg8qyza2cqgqq8250t2ye0eyy9nsvqd9v8vr4u2ykjda7qzkfwqs
const MAIN_PRIVATE_KEY3 = '0xd7d8106165aa18acf855fe3521d0c733ec6ad5afae2e1ff06687a0e790d02910'
// ckt1qrfrwcdnvssswdwpn3s9v8fp87emat306ctjwsm3nmlkjg8qyza2cqgqqx647vu0qp89npn9zvpwr33q5agwgfjr85svsmug

const TO_AXON_ADDRESS = '0xCb9112D826471E7DEB7Bc895b1771e5d676a14AF'

const AXON_RPC_RUL = 'http://axon-rpc-url'

// Calculate the actual occupied space according to the mock tx output cell
const OUTPUT_CAPACITY = BigInt(106) * BigInt(100000000)
// blake2b_hash(AlwaysSuccessScript)(https://github.com/jjyr/ckb-always-success-script/blob/master/c/always_success.c)
const AXON_TYPE_CODE_HASH = "0xe683b04139344768348499c23eb1326d5a52d6db006c0d2fece00a831f3660d7"
// The deployment tx hash of always success script(https://github.com/jjyr/ckb-always-success-script/blob/master/c/always_success.c)
const ALWAYS_SUCCESS_TX_HASH = "0xe3c81d510c2e71c4e259abce3884e80f7563b4088a8100b967278e8f179c92c4"

// blake2b_hash("DummyInputOutpointTxHash")
const AXON_INPUT_OUT_POINT_TX_HASH = "0x224b7960223b7ead6bc6e559925456696b9fc309ca5668e32fc69b4ebe25bb66"

const buildNativeCKBTx = async (privateKey, axonUnsignedHash) => {
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
  const key = keyFromPrivate(privateKey, SigAlg.Secp256r1)
  rawTx.witnesses[0].lock = calcSignedWitnessLock(key, rawTx)
  // console.log(JSON.stringify(rawTx))
  return rawTx
}

const toBuffer = input => Buffer.from(remove0x(input), 'hex')

const signAxonTxWithMainkey = async (privateKey, lock, axonTx) => {
  const signedTx = await buildNativeCKBTx(privateKey, axonTx.unsignedHash)

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

const axonAddressFromLock = (lock) => `0x${keccak160(scriptToHash(lock))}`

const transferWithMainkey = async (privateKey, lock, txCount) => {
  const provider = new JsonRpcProvider(AXON_RPC_RUL)
  const axonAddress = axonAddressFromLock(lock)
  
  let axonTx = new Transaction()
  axonTx.from = axonAddress
  axonTx.to = TO_AXON_ADDRESS
  axonTx.value = parseEther('0.01')
  axonTx.chainId = 2022
  axonTx.type = 0
  axonTx.from = axonAddress
  axonTx.gasLimit = 21000
  axonTx.gasPrice = parseUnits("0.1", "gwei");
  axonTx.nonce = txCount

  axonTx = await signAxonTxWithMainkey(privateKey, lock, axonTx)

  const ret = await provider.send('eth_sendRawTransaction', [axonTx.serialized])

  console.log("Transfer axon with mainkey unlock: ", JSON.stringify(ret))
}

const batchTransfer = async () => {
  const provider = new JsonRpcProvider(AXON_RPC_RUL)
  const address1 = addressFromPrivateKey(MAIN_PRIVATE_KEY, SigAlg.Secp256r1)
  const lock1 = addressToScript(address1)
  // 0x9447a236092f194ac774e9aaa5294c87e3ad50fd
  const axonAddress1 = axonAddressFromLock(lock1)
  const txCount1 = await provider.getTransactionCount(axonAddress1)
  let nonce1 = txCount1
  const balance1 = await provider.getBalance(axonAddress1)
  console.log("Axon account1 balance: ", formatEther(balance1))

  
  const address2 = addressFromPrivateKey(MAIN_PRIVATE_KEY2, SigAlg.Secp256r1)
  const lock2 = addressToScript(address2)
  // 0x379c1864b16f4fb685d7e8c2e15535676b6188a0
  const axonAddress2 = axonAddressFromLock(lock2)
  const txCount2 = await provider.getTransactionCount(axonAddress2)
  let nonce2 = txCount2
  const balance2 = await provider.getBalance(axonAddress2)
  console.log("Axon account2 balance: ", formatEther(balance2))

  const address3 = addressFromPrivateKey(MAIN_PRIVATE_KEY3, SigAlg.Secp256r1)
  const lock3 = addressToScript(address3)
  // 0x6eb184f21be8ee11bce40b0a335d8299af874a4b
  const axonAddress3 = axonAddressFromLock(lock3)
  const txCount3 = await provider.getTransactionCount(axonAddress3)
  let nonce3 = txCount3
  const balance3 = await provider.getBalance(axonAddress3)
  console.log("Axon account3 balance: ", formatEther(balance3))

  setInterval(() => {
    transferWithMainkey(MAIN_PRIVATE_KEY, lock1, nonce1)
    transferWithMainkey(MAIN_PRIVATE_KEY2, lock2, nonce2)
    transferWithMainkey(MAIN_PRIVATE_KEY3, lock3, nonce3)

    nonce1++
    nonce2++
    nonce3++
  }, 20)

}

batchTransfer()
