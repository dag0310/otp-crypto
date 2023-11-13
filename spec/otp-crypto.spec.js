import OtpCrypto from '../src/otp-crypto.js'

describe('OtpCrypto', function () {
  it('xorByteArrays calculates correctly', function () {
    // given
    const messageBytes = new Uint8Array([0b00000001, 0b00000010, 0b00000011])
    const keyBytes = new Uint8Array([0b00000001, 0b00000001, 0b00000001])
    const expectedBytes = new Uint8Array([0b00000000, 0b00000011, 0b00000010])

    // when
    const result = OtpCrypto.xorByteArrays(messageBytes, keyBytes)

    // then
    expect(result.resultBytes.toString()).toBe(expectedBytes.toString())
    expect(result.isKeyLongEnough).toBe(true)
  })

  it('xorByteArrays aborts if the message is longer than the key', function () {
    // given
    const messageBytes = new Uint8Array([0b00000001, 0b00000010])
    const keyBytes = new Uint8Array([0b00000001])
    const expectedBytes = new Uint8Array([0b00000000])

    // when
    const result = OtpCrypto.xorByteArrays(messageBytes, keyBytes)

    // then
    expect(result.resultBytes.toString()).toBe(expectedBytes.toString())
    expect(result.isKeyLongEnough).toBe(false)
  })

  it('Plaintext before encryption should be the same as plaintext after decryption', function () {
    // given
    let keySender = OtpCrypto.generateRandomBytes(1000)
    let keyReceiver = keySender.slice(0)
    const secretMessageUnencrypted = '°^^!§$%&/()=?1234567890ßqwertzuiopü+asdfghjklöä#yxcvbnm,.-QWERTZUIOPÜ*ASDFGHJKLÖÄ\'YXCVBNM;:_😩.'

    // when
    const otpEncrypted = OtpCrypto.encrypt(secretMessageUnencrypted, keySender)
    keySender = otpEncrypted.remainingKey

    const otpDecrypted = OtpCrypto.decrypt(otpEncrypted.base64Encrypted, keyReceiver)
    keyReceiver = otpDecrypted.remainingKey

    // then
    expect(otpDecrypted.plaintextDecrypted).toBe(secretMessageUnencrypted)
    expect(otpDecrypted.isKeyLongEnough).toBe(true)
  })

  it('Sender and receiver keys should be the same after encryption and decryption', function () {
    // given
    let keySender = OtpCrypto.generateRandomBytes(100)
    let keyReceiver = keySender.slice(0)
    const secretMessageUnencrypted = 'TOP SECRET MESSAGE.'

    // when
    const otpEncrypted = OtpCrypto.encrypt(secretMessageUnencrypted, keySender)
    keySender = otpEncrypted.remainingKey

    const otpDecrypted = OtpCrypto.decrypt(otpEncrypted.base64Encrypted, keyReceiver)
    keyReceiver = otpDecrypted.remainingKey

    // then
    expect(keySender.length).toBe(keyReceiver.length)
    expect(keySender.toString()).toBe(keyReceiver.toString())
    expect(otpEncrypted.remainingKey.every((_, idx) => otpEncrypted.remainingKey[idx] === otpDecrypted.remainingKey[idx])).toBe(true)
    expect(otpEncrypted.isKeyLongEnough).toBe(true)
  })

  it('Remaining key should be correctly shortened after encryption', function () {
    // given
    const initialKey = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    const plaintext = 'A'

    // when
    const otpEncrypted = OtpCrypto.encrypt(plaintext, initialKey)

    // then
    expect(otpEncrypted.remainingKey.length).toBe(initialKey.length - otpEncrypted.bytesUsed)
    expect(otpEncrypted.remainingKey.toString()).toBe(initialKey.slice(otpEncrypted.bytesUsed).toString())
    expect(otpEncrypted.isKeyLongEnough).toBe(true)
  })

  it('Encryption should be incomplete if key not long enough', function () {
    // given
    const key = [100]
    const plaintextUnencrypted = 'THIS MESSAGE IS TOO LONG.'

    // when
    const otpCryptoResult = OtpCrypto.encrypt(plaintextUnencrypted, key)

    // then
    expect(otpCryptoResult.isKeyLongEnough).toBe(false)
    expect(otpCryptoResult.bytesUsed).toBe(1)
    expect(otpCryptoResult.remainingKey.toString()).toBe('')
    expect(otpCryptoResult.base64Encrypted).toBe('MA==')
  })

  it('Decryption should be incomplete if key not long enough', function () {
    // given
    const key = [100]
    const base64Encrypted = 'MC0=' // This encrypted message is too long

    // when
    const otpCryptoResult = OtpCrypto.decrypt(base64Encrypted, key)

    // then
    expect(otpCryptoResult.isKeyLongEnough).toBe(false)
    expect(otpCryptoResult.bytesUsed).toBe(1)
    expect(otpCryptoResult.remainingKey.toString()).toBe('')
    expect(otpCryptoResult.plaintextDecrypted).toBe('T')
  })

  it('Encryption with no key but message should work', function () {
    // given
    const key = []
    const plaintextUnencrypted = 'test'

    // when
    const otpCryptoResult = OtpCrypto.encrypt(plaintextUnencrypted, key)

    // then
    expect(otpCryptoResult.isKeyLongEnough).toBe(false)
    expect(otpCryptoResult.bytesUsed).toBe(0)
    expect(otpCryptoResult.remainingKey.toString()).toBe('')
    expect(otpCryptoResult.base64Encrypted).toBe('')
  })

  it('Encryption with no key and no message should work', function () {
    // given
    const key = []
    const plaintextUnencrypted = ''

    // when
    const otpCryptoResult = OtpCrypto.encrypt(plaintextUnencrypted, key)

    // then
    expect(otpCryptoResult.isKeyLongEnough).toBe(true)
    expect(otpCryptoResult.bytesUsed).toBe(0)
    expect(otpCryptoResult.remainingKey.toString()).toBe('')
    expect(otpCryptoResult.base64Encrypted).toBe('')
  })

  it('Decryption with no key but message should work', function () {
    // given
    const key = []
    const base64Encrypted = 'MC0=' // This encrypted message is too long

    // when
    const otpCryptoResult = OtpCrypto.decrypt(base64Encrypted, key)

    // then
    expect(otpCryptoResult.isKeyLongEnough).toBe(false)
    expect(otpCryptoResult.bytesUsed).toBe(0)
    expect(otpCryptoResult.remainingKey.toString()).toBe('')
    expect(otpCryptoResult.plaintextDecrypted).toBe('')
  })

  it('Decryption with no key and no message should work', function () {
    // given
    const key = []
    const base64Encrypted = ''

    // when
    const otpCryptoResult = OtpCrypto.decrypt(base64Encrypted, key)

    // then
    expect(otpCryptoResult.isKeyLongEnough).toBe(true)
    expect(otpCryptoResult.bytesUsed).toBe(0)
    expect(otpCryptoResult.remainingKey.toString()).toBe('')
    expect(otpCryptoResult.plaintextDecrypted).toBe('')
  })

  it('Bytes generated randomly should have the specified amount', function () {
    // given, when, then
    expect(OtpCrypto.generateRandomBytes(30).length).toBe(30)
  })
})
