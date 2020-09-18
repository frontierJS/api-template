import { env, Model } from '@frontierjs/backend';
import helmet from 'helmet';
import cors from 'cors';
import express from 'express';
import bodyParser from 'body-parser';
import vld from 'indicative/validator.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import crypto from 'crypto';

let REFRESH_TOKEN_SECRET = env.get('REFRESH_TOKEN_SECRET');
let ACCESS_TOKEN_SECRET = env.get('ACCESS_TOKEN_SECRET');
let BCRYPT_LEVEL = env.get('BCRYPT_LEVEL', 11);

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
    super();
    this.id = id;
    this.email = email;
    this.password = password;
    this.date_added = date_added;
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
    let data = this._getWhere('email', email);
    return data ? new this(data) : null
  }
  static async validateThenStore({ email, password }) {
    //TODO: this should respond the same way: we have sent a confirmation email!
    if (this.emailTaken(email)) return res.sendStatus(401)
    let user = this.create({ email });

    let salt = user.id + user.created_at + user.deleted_at;
    let pw = this.sha512(password, salt);
    let hpw = await til(bcrypt.hash(pw, BCRYPT_LEVEL));
    let epw = encrypt(hpw);
    user.update({ password: epw });
    return user
  }
  static emailTaken(email) {
    return this._getWhere('email', email)
  }

  async auth(password) {
    let sql = 'SELECT salt, password FROM users where id = $id';
    let { epw } = this._.raw(sql, { id: this.id }) || {};
    let dpw = decrypt(epw);
    let pw = sha256(password, salt);
    if (await bcrypt.compare(pw, dpw)) return 'success'
    else return null
  }
  login() {
    let accessToken = this.generateAccessToken(ACCESS_TOKEN_SECRET);
    let refreshToken = this.generateAccessToken(REFRESH_TOKEN_SECRET);
    return { accessToken, refreshToken }
  }
  generateAccessToken(token, expiration = '24h') {
    return jwt.sign({ id: this.id, email: this.email }, token, {
      expiresIn: expiration,
    })
  }
  sha256(password, salt) {
    var hash = crypto.createHmac('sha256', salt); /** Hashing algorithm sha256 */
    hash.update(password);
    var value = hash.digest('hex');
    const buff = Buffer.from(value, 'utf-8');
    const base64 = buff.toString('base64');
    return base64
  }
}

console.log(vld);
const PEPPER = env.get('PEPPER');
const ACCESS_TOKEN_SECRET$1 = env.get('ACCESS_TOKEN_SECRET');
const REFRESH_TOKEN_SECRET$1 = env.get('REFRESH_TOKEN_SECRET');

function til$1(p) {
  return p.then((res) => [null, res]).catch((e) => [e])
}

const AuthController = {
  async register(req, res) {
    let [err, data] = await til$1(
      vld.validate(req.body, {
        email: User.rules('email'),
        password: User.rules('password'),
      })
    );

    if (err) return res.sendStatus(401)

    res.status(201).send(await User.validateThenStore(user));
  },
  async login({ body: { email, password } }, res) {
    let user = User.findByEmail(email);
    if (!user) return res.sendStatus(401)

    try {
      if (await user.auth(password)) {
        let { accessToken, refreshToken } = await user.login();
        refreshTokens.push(refreshToken);
        res.json({ accessToken: accessToken, refreshToken: refreshToken, user });
      } else {
        return res.sendStatus(401)
      }
    } catch (e) {
      console.log(e);
      return res.status(401).json({ message: 'You are not registered!' })
    }
  },

  refresh(req, res) {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.sendStatus(401)
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)

    jwt.verify(refreshToken, REFRESH_TOKEN_SECRET$1, async (err, userData) => {
      if (err) return res.sendStatus(403)
      let user = User.find(userData.id);
      let { accessToken } = await user.login();
      res.json({ accessToken });
    });
  },

  async verify(req, res) {
    res.json({ message: 'Valid Token', user: req.user });
  },

  logout(req, res) {
    //reqork this into DB
    refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
    res.sendStatus(204);
  },
  // Middleware Testing
  authenticateTokenMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).send({ error: 'denied' })

    jwt.verify(token, ACCESS_TOKEN_SECRET$1, (err, user) => {
      if (err) return res.status(403).send({ error: 'unauthorized' })
      req.user = user;
      next();
    });
  },
};

let ACCESS_TOKEN_SECRET$2 = env.get('ACCESS_TOKEN_SECRET');
let REFRESH_TOKEN_SECRET$2 = env.get('REFRESH_TOKEN_SECRET');

const UserController = {
  index(req, res) {
    let users = User._getAll();
    return res.json(users)
  },
  all(req, res) {
    let users = User.getAll({ withDeleted: true })[0]._._getAll({
      withDeleted: true,
    });
    return res.json(users)
  },
  async store(req, res) {
    let user = ({ email, password } = req.body);
    res.status(201).send(await User.validateThenStore(user));
  },
  destroy(req, res) {
    User.delete(parseInt(req.params.id));

    return res.json({ ok: true })
  },
  restore({ params: { id } }, res) {
    let user = User.restore(parseInt(id));
    console.log({ user });
    res.json(user);
  },
  logout(req, res) {
    //reqork this into DB
    refreshTokens = refreshTokens.filter((token) => token !== req.body.token);
    res.sendStatus(204);
  },
  // Middleware Testing
  authenticateTokenMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401)

    jwt.verify(token, ACCESS_TOKEN_SECRET$2, (err, user) => {
      if (err) return res.sendStatus(403)
      req.user = user;
      next();
    });
  },
};

//register, login, logout, refreshtokens, verify
let router = express.Router();
router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());

router.use('/', (req, res, next) => {
  // console.log({body: req.body})
  next();
});

// router.use('/template', TemplateRouter)

router.get(
  '/users',
  AuthController.authenticateTokenMiddleware,
  UserController.index
);
router.get('/users/free', UserController.index);
router.get(
  '/users/all',
  AuthController.authenticateTokenMiddleware,
  UserController.all
);
router.post('/users', UserController.store);
router.delete('/users/:id', UserController.destroy);
router.patch('/users/:id/restore', UserController.restore);

router.post('/register', AuthController.register);
router.post('/login', AuthController.login);
router.post('/refresh', AuthController.refresh);
router.get(
  '/verify',
  AuthController.authenticateTokenMiddleware,
  AuthController.verify
);
router.post('/logout', AuthController.logout);

let server = express();

server.use(cors());
server.use(helmet());
server.use(helmet.hidePoweredBy({ setTo: 'PHP 3.3.0' }));
server.use('/api/v1', router);

let port = env.get('PORT');

server.listen(port, () =>
  console.log(`
  Server listening on port ${port}!
`)
);
