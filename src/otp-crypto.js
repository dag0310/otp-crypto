(function (root, factory) {
  'use strict'

  if (typeof exports === 'object') {
    module.exports = factory() // CommonJS
  } else {
    root.OtpCrypto = factory() // Browser global
  }
}(this, function () {
  'use strict'

  const OtpCrypto = {}

  const encryptedDataConverter = {
    strToBytes: string => new Uint8Array(string.split('').map(char => char.codePointAt(0))),
    bytesToStr: bytes => {
      let string = ''
      bytes.forEach(byte => { string += String.fromCodePoint(byte) })
      return string
    }
  }

  const decryptedDataConverter = {
    strToBytes: string => (new window.TextEncoder()).encode(string),
    bytesToStr: bytes => (new window.TextDecoder()).decode(bytes)
  }

  const xorByteArrays = function (messageBytes, keyBytes) {
    if (messageBytes.length > keyBytes.length) {
      return null
    }
    const resultBytes = new Uint8Array(messageBytes.length)
    for (let idx = 0; idx < messageBytes.length; idx++) {
      resultBytes[idx] = messageBytes[idx] ^ keyBytes[idx]
    }
    return resultBytes
  }

  const encrypt = xorByteArrays

  const decrypt = xorByteArrays

  OtpCrypto.encrypt = function (plaintext, key) {
    const bytesUnencrypted = decryptedDataConverter.strToBytes(plaintext)
    const bytesEncrypted = encrypt(bytesUnencrypted, key)
    if (bytesEncrypted === null) {
      return null
    }
    const stringEncrypted = encryptedDataConverter.bytesToStr(bytesEncrypted)
    const base64Encrypted = window.btoa(stringEncrypted)
    const bytesUsed = bytesUnencrypted.length
    const remainingKey = key.slice(bytesUsed)

    return {base64Encrypted, remainingKey, bytesUsed}
  }

  OtpCrypto.decrypt = function (base64Encrypted, key) {
    const stringEncrypted = window.atob(base64Encrypted)
    const bytesEncrypted = encryptedDataConverter.strToBytes(stringEncrypted)
    const bytesDecrypted = decrypt(bytesEncrypted, key)
    if (bytesDecrypted === null) {
      return null
    }
    const plaintextDecrypted = decryptedDataConverter.bytesToStr(bytesDecrypted)
    const bytesUsed = bytesEncrypted.length
    const remainingKey = key.slice(bytesUsed)

    return {plaintextDecrypted, remainingKey, bytesUsed}
  }

  OtpCrypto.generateRandomBytes = function (numberOfBytes) {
    let randomBytes = new Uint8Array(numberOfBytes)
    window.crypto.getRandomValues(randomBytes)
    return randomBytes
  }

  return OtpCrypto
}))
