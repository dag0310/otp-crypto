describe('OtpCrypto', function () {
  const OtpCrypto = window.OtpCrypto

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
  })

  it('Encryption should be refused when the key is not long enough', function () {
    // given
    const key = OtpCrypto.generateRandomBytes(1)
    const plaintextUnencrypted = 'THIS MESSAGE IS TOO LONG.'

    // when, then
    expect(OtpCrypto.encrypt(plaintextUnencrypted, key)).toBe(null)
  })

  it('Decryption should be refused when the key is not long enough', function () {
    // given
    const key = OtpCrypto.generateRandomBytes(1)
    const base64Encrypted = 'ABCabc=='

    // when, then
    expect(OtpCrypto.decrypt(base64Encrypted, key)).toBe(null)
  })

  it('Bytes generated randomly should have the specified amount', function () {
    // given, when, then
    expect(OtpCrypto.generateRandomBytes(30).length).toBe(30)
  })
})
