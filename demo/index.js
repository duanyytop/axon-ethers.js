const {
  addressFromPrivateKey,
  blake256,
  Collector,
  getJoyIDCellDep,
  keccak160,
  keyFromPrivate,
  SigAlg,
  signSecp256r1Tx,
  utf8ToHex,
  remove0x,
  calcSignedWitnessLock,
} = require('@nervina-labs/joyid-sdk')
const { addressToScript, scriptToHash, bytesToHex } = require('@nervosnetwork/ckb-sdk-utils')
const { JsonRpcProvider } = require('../lib.commonjs/providers')
const { Transaction } = require('../lib.commonjs/transaction/transaction')
const { parseEther } = require('../lib.commonjs/utils')
const RLP = require('rlp')

const MAIN_PRIVATE_KEY = '0x4271c23380932c74a041b4f56779e5ef60e808a127825875f906260f1f657761'
// const ADDRESS = 'ckt1qrfrwcdnvssswdwpn3s9v8fp87emat306ctjwsm3nmlkjg8qyza2cqgqq9sfrkfah2cj79nyp7e6p283ualq8779rscnjmrj'
const TO_AXON_ADDRESS = '0xCb9112D826471E7DEB7Bc895b1771e5d676a14AF'

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
    ckbNodeUrl: 'http://127.0.0.1:8114',
    ckbIndexerUrl: 'http://127.0.0.1:8114',
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
  console.log('Axon address', axonAddress)

  // const provider = new JsonRpcProvider(AXON_RPC_RUL)
  let unsignedTx = new Transaction()
  unsignedTx.from = axonAddress
  unsignedTx.to = TO_AXON_ADDRESS
  unsignedTx.value = parseEther('1.0')
  unsignedTx.chainId = 5
  unsignedTx.from = axonAddress

  const signedTx = await buildCKBTx(lock, unsignedTx.unsignedHash)

  const sigR = [
    [toBuffer(signedTx.cellDeps[0].outPoint.txHash), toBuffer(signedTx.cellDeps[0].outPoint.index), 1],
    [],
    [toBuffer(lock.codeHash), toBuffer(lock.args), 2],
  ]

  const rlpSigR = RLP.encode(sigR)
  console.log(bytesToHex(rlpSigR))

  console.log(signedTx.witnesses[0])
  const sigS = [[toBuffer(signedTx.witnesses[0].lock), [], []]]

  const rlpSigS = RLP.encode(sigS)
  console.log(bytesToHex(rlpSigS))
}

start()
