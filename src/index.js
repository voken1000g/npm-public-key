const base32 = require('@voken/base32')
const EC = require('elliptic').ec
const ec = new EC('secp256k1')

const compress = function (input) {
  const ecKeyPair = ec.keyFromPublic(_compress(input))

  let compressed
  if (ecKeyPair.getPublic().y.isEven()) {
    compressed = Buffer.from('02' + ecKeyPair.getPublic().x.toString('hex'), 'hex')
  } else {
    compressed = Buffer.from('03' + ecKeyPair.getPublic().x.toString('hex'), 'hex')
  }

  if (compressed.length !== 33) {
    throw new InvalidPublicKeyError('Invalid Public Key')
  }

  return compressed
}

const _compress = function (input) {
  // if (!Buffer.isBuffer(input)) {
  //   input = Buffer.from(input)
  // }

  let _compressed

  if (input.length === 65) {

    if (input.slice(0, 1).toString('hex') !== '04') {
      throw new InvalidStartError('A uncompressed Public Key should start with `04`')
    }

    const ecKeyPair = ec.keyFromPublic(input)
    if (ecKeyPair.getPublic().y.isEven()) {
      _compressed = Buffer.from('02' + ecKeyPair.getPublic().x.toString('hex'), 'hex')
    } else {
      _compressed = Buffer.from('03' + ecKeyPair.getPublic().x.toString('hex'), 'hex')
    }

  } else if (input.length === 33) {

    if (
      input.slice(0, 1).toString('hex') !== '02'
      &&
      input.slice(0, 1).toString('hex') !== '03'
    ) {
      throw new InvalidStartError('A compressed Public Key should start with `02` or `03`')
    }

    _compressed = input

  } else {
    throw new InvalidLengthError('The length of a Public Key should be `65` or `33`')
  }

  if (_compressed.length !== 33) {
    throw new InvalidPublicKeyError('Invalid Public Key')
  }

  return _compressed
}

const decompress = function (input) {
  const ecKeyPair = ec.keyFromPublic(compress(input))

  return Buffer.concat([
    Buffer.from('04', 'hex'),
    Buffer.from(ecKeyPair.getPublic().x.toString('hex'), 'hex'),
    Buffer.from(ecKeyPair.getPublic().y.toString('hex'), 'hex'),
  ])
}

const isCompressed = function (input) {
  return compress(input).equals(input)
}


const assertCompressed = function (input) {
  if (!isCompressed(input)) {
    throw new InvalidUncompressedPublicKey('Invalid compressed Public Key')
  }

  return input
}

const isUncompressed = function (input) {
  return decompress(input).equals(input)
}

const assertUncompressed = function (input) {
  if (!isUncompressed(input)) {
    throw new InvalidUncompressedPublicKey('Invalid uncompressed Public Key')
  }

  return input
}

const fromHex = function (input) {
  return compress(Buffer.from(input, 'hex'))
}

const fromVPub = function (vpub) {
  if (!vpub instanceof String) {
    throw TypeError('Except: String')
  }

  if ('vpub' !== vpub.slice(0, 4)) {
    throw new InvalidStartError('A VOKEN Public Key should start with `vpub`')
  }

  if (vpub.length !== 57) {
    throw new InvalidLengthError('The length of a VOKEN Public Key should be `57`')
  }

  return compress(base32.decode(vpub.slice(4)))
}

const fromPrivateKey = function (input) {
  if (input.length !== 32) {
    throw new InvalidLengthError('The length of a Private Key should be `32`')
  }

  const ecKeyPair = ec.keyFromPrivate(input)

  let bufX = Buffer.from(ecKeyPair.getPublic().x.toArray())

  if (ecKeyPair.getPublic().y.isEven()) {
    return Buffer.concat([Buffer.from('02', 'hex'), bufX])
  }

  return Buffer.concat([Buffer.from('03', 'hex'), bufX])
}

const toVPub = function (input) {
  const compressed = compress(input)

  return 'vpub' + base32.encode(compressed)
}

class InvalidStartError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidStartError';
    this.code = 'INVALID_START'
  }
}

class InvalidLengthError extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidLengthError";
    this.code = 'INVALID_LENGTH'
  }
}

class InvalidPublicKeyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidPublicKeyError';
    this.code = 'INVALID_PUBLIC_KEY'
  }
}

class InvalidUncompressedPublicKey extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidUncompressedPublicKey';
    this.code = 'INVALID_UNCOMPRESSED_PUBLIC_KEY'
  }
}

module.exports = {
  compress: compress,
  decompress: decompress,

  isCompressed: isCompressed,
  assertCompressed: assertCompressed,

  isUncompressed: isUncompressed,
  assertUncompressed: assertUncompressed,

  fromHex: fromHex,
  fromVPub: fromVPub,
  fromPrivateKey: fromPrivateKey,

  toVPub: toVPub,

  InvalidStartError: InvalidStartError,
  InvalidLengthError: InvalidLengthError,
}
