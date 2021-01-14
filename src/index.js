const base32 = require('@voken/base32')
const EC = require('elliptic').ec
const ec = new EC('secp256k1')

const buf02 = Buffer.from('02', 'hex')
const buf03 = Buffer.from('03', 'hex')
const buf04 = Buffer.from('04', 'hex')

const compress = function (input) {
  // if (!Buffer.isBuffer(input)) {
  //   input = Buffer.from(input)
  // }

  const start = input.slice(0, 1)

  if (input.length === 65) {
    if (!buf04.equals(start)) {
      throw new InvalidStartError('A uncompressed Public Key should start with `04`')
    }

    const ecKeyPair = ec.keyFromPublic(input)
    const compressed = Buffer.from(ecKeyPair.pub.encodeCompressed())
    const decompressed = decompress(compressed)
    if (input.equals(decompressed)) {
      return compressed
    }

    throw new InvalidUncompressedPublicKey('Invalid uncompressed Public Key')
  }

  if (input.length === 33) {
    if (!buf02.equals(start) && !buf03.equals(start)) {
      throw new InvalidStartError('A compressed Public Key should start with `02` or `03`')
    }

    const ecKeyPair = ec.keyFromPublic(input)
    return Buffer.from(ecKeyPair.pub.encodeCompressed())
  }

  throw new InvalidLengthError('The length of a Public Key should be `65` or `33`')
}

const decompress = function (input) {
  const ecKeyPair = ec.keyFromPublic(compress(input))
  return Buffer.from(ecKeyPair.pub.encode())
}

const isCompressed = function (input) {
  return input.equals(compress(input))
}

const assertCompressed = function (input) {
  if (!isCompressed(input)) {
    throw new InvalidCompressedPublicKey('Invalid compressed Public Key')
  }

  return input
}

const isUncompressed = function (input) {
  return input.equals(decompress(input))
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
  const bufX = Buffer.from(ecKeyPair.getPublic().x.toArray())
  return ecKeyPair.getPublic().y.isEven() ? Buffer.concat([buf02, bufX]) : Buffer.concat([buf03, bufX])
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

class InvalidCompressedPublicKey extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidCompressedPublicKey';
    this.code = 'INVALID_COMPRESSED_PUBLIC_KEY'
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
  InvalidCompressedPublicKey: InvalidCompressedPublicKey,
  InvalidUncompressedPublicKey: InvalidUncompressedPublicKey,
}
