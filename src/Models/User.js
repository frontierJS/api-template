import { env } from '@frontierjs/backend'
import bcrypt from 'bcrypt'
import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import { Model } from '@frontierjs/backend'

let refreshTokens = []
let REFRESH_TOKEN_SECRET = env.get('REFRESH_TOKEN_SECRET')
let ACCESS_TOKEN_SECRET = env.get('ACCESS_TOKEN_SECRET')
let BCRYPT_LEVEL = env.get('BCRYPT_LEVEL', 11)

function til(p) {
  return p.then((res) => [null, res]).catch((e) => [e])
}

class User extends Model {
  constructor({
    id = null,
    email = '',
    password = '',
    date_added = new Date().toJSON(),
  } = {}) {
    super()
    this.id = id
    this.email = email
    this.password = password
    this.date_added = date_added
    return this
  }
  static get useSoftDeletes() {
    return true
  }
  static get hidden() {
    return ['password']
  }
  static get guarded() {
    return ['is_deleted', 'date_added']
  }
  static get fields() {
    return [
      {
        name: 'id',
        type: 'integer',
        opts: 'NOT NULL PRIMARY KEY AUTOINCREMENT',
      },
      { name: 'email', type: 'text', rules: 'required|email' },
      { name: 'password', type: 'text', rules: 'required|min:8' },
      { name: 'created_at', type: 'text' },
      { name: 'updated_at', type: 'text' },
      { name: 'deleted_at', type: 'text' },
    ]
  }
  static rules(field) {
    return this.fields.filter((f) => f.name == field).pop().rules
  }
  static findByEmail(email) {
    let data = this._getWhere('email', email)
    return data ? new this(data) : null
  }
  static async validateThenStore({ email, password }) {
    //TODO: this should respond the same way: we have sent a confirmation email!
    if (this.emailTaken(email)) return res.sendStatus(401)
    let user = this.create({ email })

    let salt = user.id + user.created_at + user.deleted_at
    let pw = this.sha512(password, salt)
    let hpw = await til(bcrypt.hash(pw, BCRYPT_LEVEL))
    let epw = encrypt(hpw)
    user.update({ password: epw })
    return user
  }
  static emailTaken(email) {
    return this._getWhere('email', email)
  }

  async auth(password) {
    let sql = 'SELECT salt, password FROM users where id = $id'
    let { epw } = this._.raw(sql, { id: this.id }) || {}
    let dpw = decrypt(epw)
    let pw = sha256(password, salt)
    if (await bcrypt.compare(pw, dpw)) return 'success'
    else return null
  }
  login() {
    let accessToken = this.generateAccessToken(ACCESS_TOKEN_SECRET)
    let refreshToken = this.generateAccessToken(REFRESH_TOKEN_SECRET)

    refreshTokens.push(refreshToken)
    return { accessToken, refreshToken }
  }
  generateAccessToken(token, expiration = '24h') {
    return jwt.sign({ id: this.id, email: this.email }, token, {
      expiresIn: expiration,
    })
  }
  sha256(password, salt) {
    var hash = crypto.createHmac('sha256', salt) /** Hashing algorithm sha256 */
    hash.update(password)
    var value = hash.digest('hex')
    const buff = Buffer.from(value, 'utf-8')
    const base64 = buff.toString('base64')
    return base64
  }
}

export default User
