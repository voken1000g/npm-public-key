const publicKey = require('../src')
const privateKey = require('@voken/private-key')
const address = require('@voken/address')

// const bufPrivateKey = privateKey.fromVPriv('vprivPWT238x13x4y140N3dqqF0EgKd2VN9ruB7Bp7wyekyn8ynMH53h0')
// console.log('bufPrivateKey:', bufPrivateKey)
//
// const bufPublicKey = publicKey.fromPrivateKey(bufPrivateKey)
// console.log('bufPublicKey:', bufPublicKey)

const bufPublicKey = publicKey.fromVPub('vpub0C1xPKak7gV71M1vA3k4J2k2hQ3Q0SeRrAU2R8ptKcH5cTu26eyPX')
console.log('bufPublicKey:', bufPublicKey)

const bufCompressedPublicKey = publicKey.compress(bufPublicKey)
console.log('bufCompressedPublicKey:', bufCompressedPublicKey)


const strAddress = address.fromPublicKey(bufPublicKey)
console.log('strAddress:', strAddress)
