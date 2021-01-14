const publicKey = require('../src')
const privateKey = require('@voken/private-key')
const vokenAddress = require('@voken/address')

// const bufPrivateKey = privateKey.fromVPriv('vprivPWT238x13x4y140N3dqqF0EgKd2VN9ruB7Bp7wyekyn8ynMH53h0')
// console.log('bufPrivateKey:', bufPrivateKey)
//
// const bufPublicKey = publicKey.fromPrivateKey(bufPrivateKey)
// console.log('bufPublicKey:', bufPublicKey)

// const bufPublicKey = publicKey.fromVPub('vpub085Q5sJNAW3H933syBU0aM4cwXdQT92prPPEn08237T3g72njEP4p')
// // const bufPublicKey = publicKey.fromVPub('vpub09FePeh49nT6NbeekEchXnxht8y7DXAWF3Un49nuV80GXxvnbNexM')
// console.log('bufPublicKey:', bufPublicKey)
// console.log('bufPublicKey:', publicKey.toVPub(bufPublicKey))
//
// // const bufCompressedPublicKey = publicKey.compress(bufPublicKey)
// // console.log('bufCompressedPublicKey:', bufCompressedPublicKey)
//
// const bufUncompressedPublicKey = publicKey.decompress(bufPublicKey)
// console.log('bufUncompressedPublicKey:', bufUncompressedPublicKey)
//
// const strAddress = address.fromPublicKey(bufPublicKey)
// console.log('strAddress:', strAddress)


//
//
// const hexPublicKeyCompressed = '020b72e6555747148c79faf605508cef9b7d2456c5acea810219f4381c5593ac4b'
// // const hexPublicKeyCompressed = '025eeb3a244d746aadce9b991f57d1d23e76f95d78f75226bbe2010f7b955d5dea'
// console.log('hexPublicKeyCompressed:', hexPublicKeyCompressed)
//
// const bufPublicKeyCompressed = Buffer.from(hexPublicKeyCompressed, 'hex')
// console.log('bufPublicKeyCompressed:', bufPublicKeyCompressed)
//
// const bufPublicKeyUncompressed = publicKey.decompress(bufPublicKeyCompressed)
// console.log('bufPublicKeyUncompressed:', bufPublicKeyUncompressed)
// console.log('bufPublicKeyUncompressed:', bufPublicKeyUncompressed.toString('hex'))
//
// // const un = '04b72e6555747148c79faf605508cef9b7d2456c5acea810219f4381c5593ac4f62f238615e9b580c22b794607fa14b9b3d6591a12546b33f6baffa005e0754602'
// // // const un = '04b72e6555747148c79faf605508cef9b7d2456c5acea810219f4381c5593ac4f6693fc8bba360471210c9ce4ac07fe39e3be36c10b7ac7665eb59011001df0428'
// // //
// // const bufUncompressed = Buffer.from(un, 'hex')
// // // console.log(publicKey.assertUncompressed(bufUncompressed))
// //
// // const compressedUnsafe = publicKey.compressUnsafe(bufUncompressed)
// // console.log('compressedUnsafe:', compressedUnsafe)
// //
// // const compressed = publicKey.compress(bufUncompressed)
// // console.log('compressed:', compressed)
// //
//
// const buf = Buffer.from('045eeb3a244d746aadce9b991f57d1d23e76f95d78f75226bbe2010f7b955d5dea3c8fece8c6780eca93ce613b2055bd09937c48e8a9e15ee4c350a1b1e1529f36', 'hex')
// const isUncompressed = publicKey.isUncompressed(buf)
//
// console.log('isUncompressed:', isUncompressed)


//
// const hexCompressed = '0303eb4d533c3870d03c50e6490a628dc77065d8c2b62c22da9b22566b6233bf6f'
// console.log('hexCompressed:', hexCompressed)
//
//
// const bufPublicKey = publicKey.fromHex(hexCompressed)
// // console.log('bufPublicKey:', bufPublicKey)
// console.log(' bufPublicKey:', bufPublicKey.toString('hex'))
//
//
// const bufCompressed = Buffer.from(hexCompressed, 'hex')
// console.log('bufCompressed:', bufCompressed)
//
// // const assertCompressed = publicKey.assertCompressed(bufCompressed)
// // console.log('assertCompressed:', assertCompressed)
//
// const bufCompressedConfirm = publicKey.compress(bufCompressed)
// console.log('bufCompressedConfirm:', bufCompressedConfirm)
//
// const vpub = publicKey.toVPub(bufCompressed)
// console.log('vpub:', vpub)
//
// const address = vokenAddress.fromPublicKey(bufCompressed)
// console.log('address:', address)

// 03d172966187c0a864fe2069d2cbf039eb7169f14821acf5120761f756adaf57c0
// vpub0F8q55K1gY0aGs7x41MW5jYg77nq2tFh90GtSw8j0WGyEnndNWBV0

// Unknown point format
// 02007ba15ae1f2d415a6cdb2c6d645dc364253017bbf4bfd59503c824de2119be0
// 02000eca78980edf9934f72f3db6cbcd320cb3b011d2c1553cd0b2bcd2e0c8018b

const ori = '045eeb3a244d746aadce9b991f57d1d23e76f95d78f75226bbe2010f7b955d5dea3c8fece8c6780eca93ce613b2055bd09937c48e8a9e15ee4c350a1b1e1529f36'
const buf = Buffer.from(ori, 'hex')
const rs = publicKey.compress(buf)
// const de = publicKey.decompress(buf)
console.log('ori:', ori)
console.log('buf:', buf)
console.log('rs:', rs.toString('hex'))
// console.log('de:', de.toString('hex'))
