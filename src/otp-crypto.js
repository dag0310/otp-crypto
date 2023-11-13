class OtpCrypto {
  static encryptedDataConverter = {
    strToBytes: string => new Uint8Array(string.split('').map(char => char.codePointAt(0))),
    bytesToStr: bytes => {
      let string = ''
      bytes.forEach(byte => { string += String.fromCodePoint(byte) })
      return string
    },
    base64ToBytes (base64) { return this.strToBytes(atob(base64)) },
    bytesToBase64 (bytes) { return btoa(this.bytesToStr(bytes)) },
  }

  static decryptedDataConverter = {
    strToBytes: string => new TextEncoder().encode(string),
    bytesToStr: bytes => new TextDecoder().decode(bytes),
    base64ToBytes (base64) { return this.strToBytes(atob(base64)) },
    bytesToBase64 (bytes) { return btoa(this.bytesToStr(bytes)) },
  }

  static xorByteArrays = function (messageBytes, keyBytes) {
    const isKeyLongEnough = keyBytes.length >= messageBytes.length
    const minLength = Math.min(messageBytes.length, keyBytes.length)
    const resultBytes = new Uint8Array(minLength)
    for (let idx = 0; idx < minLength; idx++) {
      resultBytes[idx] = messageBytes[idx] ^ keyBytes[idx]
    }
    return { resultBytes, isKeyLongEnough }
  }

  static encrypt (plaintext, keyBytes) {
    const bytesUnencrypted = this.decryptedDataConverter.strToBytes(plaintext)
    const bytesEncrypted = this.xorByteArrays(bytesUnencrypted, keyBytes)
    const stringEncrypted = this.encryptedDataConverter.bytesToStr(bytesEncrypted.resultBytes)
    const base64Encrypted = btoa(stringEncrypted)
    const bytesUsed = bytesEncrypted.resultBytes.length
    const remainingKey = keyBytes.slice(bytesUsed)
    const isKeyLongEnough = bytesEncrypted.isKeyLongEnough
    return { base64Encrypted, remainingKey, bytesUsed, isKeyLongEnough }
  }

  static decrypt (base64Encrypted, keyBytes) {
    const stringEncrypted = atob(base64Encrypted)
    const bytesEncrypted = this.encryptedDataConverter.strToBytes(stringEncrypted)
    const bytesDecrypted = this.xorByteArrays(bytesEncrypted, keyBytes)
    const plaintextDecrypted = this.decryptedDataConverter.bytesToStr(bytesDecrypted.resultBytes)
    const bytesUsed = bytesDecrypted.resultBytes.length
    const remainingKey = keyBytes.slice(bytesUsed)
    const isKeyLongEnough = bytesDecrypted.isKeyLongEnough
    return { plaintextDecrypted, remainingKey, bytesUsed, isKeyLongEnough }
  }

  static generateRandomBytes (numberOfBytes) {
    return crypto.getRandomValues(new Uint8Array(numberOfBytes))
  }
}

export default OtpCrypto
