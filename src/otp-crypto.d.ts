declare module 'otp-crypto' {
  interface DataConverter {
    strToBytes: (str: string) => Uint8Array;
    bytesToStr: (bytes: Uint8Array) => string;
    base64ToBytes: (base64: string) => Uint8Array;
    bytesToBase64: (bytes: Uint8Array) => string;
  }
  class OtpCrypto {
    static encryptedDataConverter: DataConverter;
    static decryptedDataConverter: DataConverter;
    static xorByteArrays (messageBytes: Uint8Array, keyBytes: Uint8Array): { resultBytes: Uint8Array, isKeyLongEnough: boolean };
    static encrypt (plaintext: string, keyBytes: Uint8Array): { base64Encrypted: string, remainingKey: Uint8Array, bytesUsed: number, isKeyLongEnough: boolean };
    static decrypt (base64Encrypted: string, keyBytes: Uint8Array): { plaintextDecrypted: string, remainingKey: Uint8Array, bytesUsed: number, isKeyLongEnough: boolean };
    static generateRandomBytes(numberOfBytes: number): Uint8Array;
  }
  export default OtpCrypto;
}
