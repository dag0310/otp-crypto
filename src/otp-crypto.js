(function (root, factory) {
  'use strict'

  if (typeof exports === 'object') {
    module.exports = factory() // CommonJS
  } else {
    root.OtpCrypto = factory() // Browser global
  }
}(this, function () {
  'use strict'

  const isNodeJs = typeof window === 'undefined' && typeof global !== 'undefined'

  const envAtob = function (base64) {
    if (isNodeJs) {
      const buffer = require('buffer')
      const Buffer = global.Buffer || buffer.Buffer
      return Buffer.from(base64, 'base64').toString('binary')
    }
    return window.atob(base64)
  }
  const envBtoa = function (string) {
    if (isNodeJs) {
      const buffer = require('buffer')
      const Buffer = global.Buffer || buffer.Buffer.from
      return Buffer.from(string, 'binary').toString('base64')
    }
    return window.btoa(string)
  }
  const envTextDecoder = function () {
    if (isNodeJs) {
      const textEncoding = require('text-encoding')
      const MyTextDecoder = global.TextDecoder || textEncoding.TextDecoder
      return new MyTextDecoder()
    }
    return new window.TextDecoder()
  }
  const envTextEncoder = function () {
    if (isNodeJs) {
      const textEncoding = require('text-encoding')
      const MyTextEncoder = global.TextEncoder || textEncoding.TextEncoder
      return new MyTextEncoder()
    }
    return new window.TextEncoder()
  }
  const envCryptoGetRandomValues = function (bytes) {
    if (isNodeJs) {
      const getRandomValues = require('get-random-values')
      return getRandomValues(bytes)
    }
    return window.crypto.getRandomValues(bytes)
  }

  const encryptedDataConverter = {
    strToBytes: string => new Uint8Array(string.split('').map(char => char.codePointAt(0))),
    bytesToStr: bytes => {
      let string = ''
      bytes.forEach(byte => { string += String.fromCodePoint(byte) })
      return string
    },
    base64ToBytes (base64) { return this.strToBytes(envAtob(base64)) },
    bytesToBase64 (bytes) { return envBtoa(this.bytesToStr(bytes)) }
  }

  const decryptedDataConverter = {
    strToBytes: string => envTextEncoder().encode(string),
    bytesToStr: bytes => envTextDecoder().decode(bytes),
    base64ToBytes (base64) { return this.strToBytes(envAtob(base64)) },
    bytesToBase64 (bytes) { return envBtoa(this.bytesToStr(bytes)) }
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
    const base64Encrypted = envBtoa(stringEncrypted)
    const bytesUsed = bytesEncrypted.resultBytes.length
    const remainingKey = key.slice(bytesUsed)
    const isKeyLongEnough = bytesEncrypted.isKeyLongEnough

    return {base64Encrypted, remainingKey, bytesUsed, isKeyLongEnough}
  }

  const decrypt = function (base64Encrypted, key) {
    const stringEncrypted = envAtob(base64Encrypted)
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
    envCryptoGetRandomValues(randomBytes)
    return randomBytes
  }

  return {generateRandomBytes, encrypt, decrypt, encryptedDataConverter, decryptedDataConverter, xorByteArrays}
}))
