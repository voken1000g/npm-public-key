const base32 = require('@voken/base32')
const EC = require('elliptic').ec

const ec = new EC('secp256k1')

const compress = function (input) {
  if (input.length === 65) {
    const start = input.slice(0, 1)

    if (!start.equals(Buffer.from('04', 'hex'))) {
      throw new InvalidStartError('A compressed Public Key must start with `04`')
    }

    const ecKeyPair = ec.keyFromPublic(input)

    if (ecKeyPair.getPublic().y.isEven()) {
      return Buffer.from('02' + ecKeyPair.getPublic().x.toString('hex'), 'hex')
    }

    return Buffer.from('03' + ecKeyPair.getPublic().x.toString('hex'), 'hex')
  }

  if (input.length === 33) {
    const start = input.slice(0, 1)

    if (
      !start.equals(Buffer.from('02', 'hex'))
      &&
      !start.equals(Buffer.from('03', 'hex'))
    ) {
      throw new InvalidStartError('A uncompressed Public Key must start with `02` or `03`')
    }

    return input
  }

  throw new InvalidLengthError('The length of a Public Key must be `65` or `33`')
}

const decompress = function (input) {
  const start = input.slice(0, 1)

  if (input.length === 33) {
    if (
      !start.equals(Buffer.from('02', 'hex'))
      &&
      !start.equals(Buffer.from('03', 'hex'))
    ) {
      throw new InvalidStartError('A uncompressed Public Key must start with `02` or `03`')
    }

    const ecKeyPair = ec.keyFromPublic(input)

    return Buffer.concat([
      Buffer.from('04', 'hex'),
      Buffer.from(ecKeyPair.getPublic().x.toString('hex'), 'hex'),
      Buffer.from(ecKeyPair.getPublic().y.toString('hex'), 'hex'),
    ])
  }

  if (input.length === 65) {
    if (!start.equals(Buffer.from('04', 'hex'))) {
      throw new InvalidStartError('A compressed Public Key must start with `04`')
    }

    return input
  }

  throw new InvalidLengthError('The length of a Public Key must be `65` or `33`')
}

const fromVPub = function (vpub) {
  if (!vpub instanceof String) {
    throw TypeError('Except: String')
  }

  if ('vpub' !== vpub.slice(0, 4)) {
    throw new InvalidStartError('A VOKEN Public Key must start with `vpub`')
  }

  vpub = vpub.slice(4)

  if (vpub.length !== 53) {
    throw new InvalidLengthError('The length of a VOKEN Public Key must be `57`')
  }

  return Buffer.from(base32.decode(vpub))
}

const fromPrivateKey = function (input) {
  if (!input.length === 32) {
    throw new InvalidLengthError('The length of a Private Key must be `32`')
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

module.exports = {
  compress: compress,
  decompress: decompress,
  fromVPub: fromVPub,
  fromPrivateKey: fromPrivateKey,
  toVPub: toVPub,
  InvalidStartError: InvalidStartError,
  InvalidLengthError: InvalidLengthError,
}
