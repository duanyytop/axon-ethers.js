const {
  addressFromPrivateKey,
  blake256,
  Collector,
  getJoyIDCellDep,
  keccak160,
  keyFromPrivate,
  SigAlg,
  utf8ToHex,
  remove0x,
  calcSignedWitnessLock,
} = require('@nervina-labs/joyid-sdk')
const { addressToScript, scriptToHash, bytesToHex } = require('@nervosnetwork/ckb-sdk-utils')
const { JsonRpcProvider } = require('../lib.commonjs/providers')
const { Transaction } = require('../lib.commonjs/transaction/transaction')
const { Signature } = require('../lib.commonjs/crypto/signature')
const { parseEther, parseUnits} = require('../lib.commonjs/utils')
const RLP = require('rlp')
const { getAddress } = require('../lib.commonjs/address')

const MAIN_PRIVATE_KEY = '0x4271c23380932c74a041b4f56779e5ef60e808a127825875f906260f1f657761'
// const ADDRESS = 'ckt1qrfrwcdnvssswdwpn3s9v8fp87emat306ctjwsm3nmlkjg8qyza2cqgqq9sfrkfah2cj79nyp7e6p283ualq8779rscnjmrj'
const TO_AXON_ADDRESS = '0xCb9112D826471E7DEB7Bc895b1771e5d676a14AF'

const AXON_RPC_RUL = 'http://axon-rpc-url'
const CKB_RPC_URL = 'http://127.0.0.1:8114'

const OUTPUT_CAPACITY = BigInt(100) * BigInt(100000000)

const buildCKBTx = async (lock, axonUnsignedHash) => {
  const typeCodeHash = `0x${blake256(utf8ToHex('AxonCellVerifier'))}`
  const output = {
    capacity: `0x${OUTPUT_CAPACITY.toString(16)}`,
    lock,
    type: {
      codeHash: typeCodeHash,
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
      previousOutput: cells[0].outPoint,
      since: '0x0',
    },
  ]
  let rawTx = {
    version: '0x0',
    cellDeps: [getJoyIDCellDep(false)],
    headerDeps: [],
    inputs,
    outputs: [output],
    outputsData: ['0x'],
    witnesses: [],
  }
  rawTx.witnesses = rawTx.inputs.map((_, i) => (i > 0 ? '0x' : { lock: '', inputType: '', outputType: '' }))
  const key = keyFromPrivate(MAIN_PRIVATE_KEY, SigAlg.Secp256r1)
  rawTx.witnesses[0].lock = calcSignedWitnessLock(key, rawTx)
  return rawTx
}

const toBuffer = input => Buffer.from(remove0x(input), 'hex')

const start = async () => {
  const address = addressFromPrivateKey(MAIN_PRIVATE_KEY, SigAlg.Secp256r1)
  const lock = addressToScript(address)
  const axonAddress = `0x${keccak160(scriptToHash(lock))}`
  console.log('CKB address', address)
  // 0x9447a236092f194ac774e9aaa5294c87e3ad50fd
  console.log('Axon address', axonAddress)

  let axonTx = new Transaction()
  axonTx.from = axonAddress
  axonTx.to = TO_AXON_ADDRESS
  axonTx.value = parseEther('1.0')
  axonTx.chainId = 2022
  axonTx.type = 0
  axonTx.from = axonAddress
  axonTx.gasLimit = 21000
  axonTx.gasPrice = parseUnits("0.14085197", "gwei");

  const signedTx = await buildCKBTx(lock, axonTx.unsignedHash)

  const sigR = [
    [toBuffer(signedTx.cellDeps[0].outPoint.txHash), toBuffer(signedTx.cellDeps[0].outPoint.index), 1],
    [],
    [toBuffer(lock.codeHash), toBuffer(lock.args), 2],
  ]
  const rlpSigR = bytesToHex(Buffer.concat([Buffer.from([2]), RLP.encode(sigR)]))
  const sigS = [[toBuffer(signedTx.witnesses[0].lock), [], []]]
  const rlpSigS = bytesToHex(RLP.encode(sigS))

  console.log(rlpSigR)

  axonTx.signature = Signature.fromUnchecked(rlpSigR, rlpSigS, 0)

  console.log("axon signed hash: ", axonTx.hash)

  console.log(JSON.stringify(axonTx))

  const provider = new JsonRpcProvider(AXON_RPC_RUL)
  console.log(axonTx.serialized)
  const ret = await provider.send('eth_sendRawTransaction', [axonTx.serialized])

  console.log(JSON.stringify(ret))
}

start()
