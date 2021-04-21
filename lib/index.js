const crypto = require('crypto')
const url = require('url')
const base32 = require('base32.js')

const truncate = (hmacResult, d) => {
  const offset = hmacResult[hmacResult.length - 1] & 0xf
  let binCode = (hmacResult.slice(offset, offset + 4).readUInt32BE(0) & 0x7fffffff)
    .toString(10)
    .substr(-d)

  while (binCode.length < d) {
    binCode = '0' + binCode
  }

  return binCode
}

class Otp {
  generateSecret(options = {}) {
    const that = this
    const bytes = crypto.randomBytes(32)
    const secret = base32.encode(bytes).replace(/=/g, '')

    options.secret = secret

    return {
      secret,
      url: that.otpauthUrl(options),
    }
  }

  otpauthUrl({
    name = 'myApp',
    type = 'totp',
    algorithm = 'SHA1',
    digits = 6,
    period = 30,
    counter,
    issuer,
    secret,
  } = {}) {
    if (!secret) {
      throw new Error('Missing secret')
    }

    const query = {
      secret,
      digits,
      algorithm,
    }

    if (type === 'totp') {
      query.period = period
    }

    if (type === 'hotp') {
      query.counter = counter
    }

    if (issuer) {
      query.issuer = issuer
    }

    return url.format({
      protocol: 'otpauth',
      slashes: true,
      hostname: type,
      pathname: encodeURIComponent(name),
      query,
    })
  }

  hotp(K, C, d = 6) {
    const buf = Buffer.alloc(8)
    let tmp = C

    for (let i = 0; i < 8; i += 1) {
      buf[7 - i] = tmp & 0xff
      tmp = tmp >> 8
    }

    const hmac = crypto.createHmac('SHA1', base32.decode(K))

    hmac.update(buf)

    return truncate(hmac.digest(), d)
  }

  totp(K, d = 6, step = 30, C = Date.now() / 1000) {
    return this.hotp(K, Math.floor(C / step), d)
  }

  verifyTotp(options) {
    const win = parseInt(options.window || 0)

    options.counter =
      parseInt(options.counter || Math.floor(Date.now() / 1000 / (options.step || 30))) -
      win

    options.window += win

    return this.verifyHotp(options)
  }

  verifyHotp(options) {
    const K = options.secret
    const d = parseInt(options.digits, 10) || 6
    const token = parseInt(options.token, 10)
    const win = parseInt(options.window, 10) || 0
    const C = parseInt(options.counter, 10) || 0

    for (let i = C; i <= C + win; i += 1) {
      if (parseInt(this.hotp(K, i, d), 10) === token) {
        return true
      }
    }

    return false
  }
}

module.exports = new Otp()
