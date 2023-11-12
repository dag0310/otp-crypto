# OTP Crypto

One-time pad crypto library for plaintext data exchange.

## Installation

`npm install otp-crypto --save`

## Demo

[Demo page](https://dag0310.github.io/otp-crypto/demo/) - can be found under `demo/index.html`

## API

```javascript
OtpCrypto.generateRandomBytes(numberOfBytes: number) // Returns: Uint8Array of random bytes
OtpCrypto.encrypt(plaintext: string, keyBytes: Uint8Array) // Returns: Object {base64Encrypted: string, remainingKey: Uint8Array, bytesUsed: number, isKeyLongEnough: boolean}
OtpCrypto.decrypt(base64Encrypted: string, keyBytes: Uint8Array) // Returns: Object {plaintextDecrypted: string, remainingKey: Uint8Array, bytesUsed: number, isKeyLongEnough: boolean}
```

## Example

```javascript
// Generate a random byte array key with a predefined length:
let keySender = OtpCrypto.generateRandomBytes(1000)
let keyReceiver = keySender.slice(0) // copy of key, which in real-life needs to be exchanged somehow

// Encrypt a message to Base64 with the sender's key:
const secretMessageUnencrypted = 'TOP SECRET MESSAGE.'
const otpEncrypted = OtpCrypto.encrypt(secretMessageUnencrypted, keySender)
keySender = otpEncrypted.remainingKey

// Decrypt the message to plaintext with the receiver's key:
const otpDecrypted = OtpCrypto.decrypt(otpEncrypted.base64Encrypted, keyReceiver)
keyReceiver = otpDecrypted.remainingKey

// Extract the decrypted message
const secretMessageDecrypted = otpDecrypted.plaintextDecrypted // 'TOP SECRET MESSAGE.'

// Now both sender and receiver have the same key again (shorter than before) and can continue sending other messages with the remaining key.
```

## Dev corner

Run linter: `npm run lint`

Run tests: `npm run test`
