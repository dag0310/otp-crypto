(function (root, factory) {
  'use strict'

  if (typeof exports === 'object') {
    module.exports = factory() // CommonJS
  } else {
    root.OtpCrypto = factory() // Browser global
  }
}(this, function () {
  'use strict'

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
    const isKeyLongEnough = keyBytes.length >= messageBytes.length
    const minLength = Math.min(messageBytes.length, keyBytes.length)
    const resultBytes = new Uint8Array(minLength)
    for (let idx = 0; idx < minLength; idx++) {
      resultBytes[idx] = messageBytes[idx] ^ keyBytes[idx]
    }
    return {resultBytes, isKeyLongEnough}
  }

  const encrypt = function (plaintext, key) {
    const bytesUnencrypted = decryptedDataConverter.strToBytes(plaintext)
    const bytesEncrypted = xorByteArrays(bytesUnencrypted, key)
    const stringEncrypted = encryptedDataConverter.bytesToStr(bytesEncrypted.resultBytes)
    const base64Encrypted = window.btoa(stringEncrypted)
    const bytesUsed = bytesEncrypted.resultBytes.length
    const remainingKey = key.slice(bytesUsed)
    const isKeyLongEnough = bytesEncrypted.isKeyLongEnough

    return {base64Encrypted, remainingKey, bytesUsed, isKeyLongEnough}
  }

  const decrypt = function (base64Encrypted, key) {
    const stringEncrypted = window.atob(base64Encrypted)
    const bytesEncrypted = encryptedDataConverter.strToBytes(stringEncrypted)
    const bytesDecrypted = xorByteArrays(bytesEncrypted, key)
    const plaintextDecrypted = decryptedDataConverter.bytesToStr(bytesDecrypted.resultBytes)
    const bytesUsed = bytesDecrypted.resultBytes.length
    const remainingKey = key.slice(bytesUsed)
    const isKeyLongEnough = bytesDecrypted.isKeyLongEnough

    return {plaintextDecrypted, remainingKey, bytesUsed, isKeyLongEnough}
  }

  const generateRandomBytes = function (numberOfBytes) {
    let randomBytes = new Uint8Array(numberOfBytes)
    window.crypto.getRandomValues(randomBytes)
    return randomBytes
  }

  return {generateRandomBytes, encrypt, decrypt}
}))
