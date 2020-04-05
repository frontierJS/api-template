'use strict';

const { env } = require('@frontierjs/backend');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Model } = require('@frontierjs/backend');
let REFRESH_TOKEN_SECRET = env.get('REFRESH_TOKEN_SECRET');
let ACCESS_TOKEN_SECRET = env.get('ACCESS_TOKEN_SECRET');

class User extends Model {
  constructor({
    id = null,
    email = '',
    password = '',
    date_added = new Date().toJSON()
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
        opts: 'NOT NULL PRIMARY KEY AUTOINCREMENT'
      },
      { name: 'email', type: 'text' },
      { name: 'password', type: 'text' },
      { name: 'date_added', type: 'text' },
      { name: 'is_deleted', type: 'text' }
    ]
  }
  static findByEmail(email) {
    let data = this._getWhere('email', email);
    return data ? new this(data) : null
  }
  static async validateThenStore({ email, password }) {
    //Need to validate data
    try {
      if (this.emailTaken(email)) return { error: 'Email Taken 1' }

      let hashedPassword = await bcrypt.hash(password, 10);
      let result = this.create({ email, password: hashedPassword });
      return result
    } catch (e) {
      return void 0
    }
  }
  static emailTaken(email) {
    return this._getWhere('email', email)
  }

  async auth(pw) {
    let sql = 'SELECT password FROM users where id = $id';
    let { password } = this._.raw(sql, { id: this.id }) || {};
    if (await bcrypt.compare(pw, password)) return 'success'
    else return null
  }
  login() {
    let accessToken = this.generateAccessToken(ACCESS_TOKEN_SECRET);
    let refreshToken = this.generateAccessToken(REFRESH_TOKEN_SECRET);
    return { accessToken, refreshToken }
  }
  generateAccessToken(token, expiration = '24h') {
    return jwt.sign({ id: this.id, email: this.email }, token, {
      expiresIn: expiration
    })
  }
}

const { env: env$1 } = require('@frontierjs/backend');
const jwt$1 = require('jsonwebtoken');

let ACCESS_TOKEN_SECRET$1 = env$1.get('ACCESS_TOKEN_SECRET');
let REFRESH_TOKEN_SECRET$1 = env$1.get('REFRESH_TOKEN_SECRET');

//fix
let refreshTokens = [
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZW1haWwiOiJ0ZXN0QGVtYWlsLmNvbSIsInBhc3N3b3JkIjoiJDJiJDEwJEJJQVVLRmJCakk2dGxHQVFxVTNHNnViQUNLS2tTZWkyUGNxRlZESE1acmU2VEJtekUwOGpTIiwiaWF0IjoxNTcyNzIzMzM2fQ.H94OYXkcQKEsaYP4m549g47ch5VfJA_1v2RtU-_JsMs'
];
const AuthController = {
  async register(req, res) {
    // console.log({req})
    //validate request
    try {
      let user = ({ email, password } = req.body);
      res.status(201).send(await User.validateThenStore(user));
    } catch (e) {
      res.status(500).send();
    }
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
      return res.status(401).json({ message: 'You are not registered!' })
    }
  },

  refresh(req, res) {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.sendStatus(401)
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)

    jwt$1.verify(refreshToken, REFRESH_TOKEN_SECRET$1, async (err, userData) => {
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
    refreshTokens = refreshTokens.filter(token => token !== req.body.token);
    res.sendStatus(204);
  },
  // Middleware Testing
  authenticateTokenMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).send({ error: 'denied' })

    jwt$1.verify(token, ACCESS_TOKEN_SECRET$1, (err, user) => {
      if (err) return res.status(403).send({ error: 'unauthorized' })
      req.user = user;
      next();
    });
  }
};

const { env: env$2 } = require('@frontierjs/backend');

const jwt$2 = require('jsonwebtoken');

let ACCESS_TOKEN_SECRET$2 = env$2.get('ACCESS_TOKEN_SECRET');
let REFRESH_TOKEN_SECRET$2 = env$2.get('REFRESH_TOKEN_SECRET');

//fix
let refreshTokens$1 = [
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZW1haWwiOiJ0ZXN0QGVtYWlsLmNvbSIsInBhc3N3b3JkIjoiJDJiJDEwJEJJQVVLRmJCakk2dGxHQVFxVTNHNnViQUNLS2tTZWkyUGNxRlZESE1acmU2VEJtekUwOGpTIiwiaWF0IjoxNTcyNzIzMzM2fQ.H94OYXkcQKEsaYP4m549g47ch5VfJA_1v2RtU-_JsMs'
];
const UserController = {
  index(req, res) {
    let users = User._getAll();
    return res.json(users)
  },
  all(req, res) {
    let users = User.getAll({ withDeleted: true })[0]._._getAll({
      withDeleted: true
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
    res.json(user);
  },
  logout(req, res) {
    //reqork this into DB
    refreshTokens$1 = refreshTokens$1.filter(token => token !== req.body.token);
    res.sendStatus(204);
  },
  // Middleware Testing
  authenticateTokenMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401)

    jwt$2.verify(token, ACCESS_TOKEN_SECRET$2, (err, user) => {
      if (err) return res.sendStatus(403)
      req.user = user;
      next();
    });
  }
};

//register, login, logout, refreshtokens, verify
let express = require('express');
let router = express.Router();

const bodyParser = require('body-parser');
router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());

router.use('/', (req, res, next) => {
  // console.log({body: req.body})
  next();
});

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

const { env: env$3 } = require('@frontierjs/backend');
const helmet = require('helmet');
const cors = require('cors');

let server = require('express')();

server.use(cors());
server.use(helmet());
server.use(helmet.hidePoweredBy({ setTo: 'PHP 3.3.0' }));
server.use('/api/v1', router);

const { env: env$4 } = require('@frontierjs/backend');

let port = env$4.get('PORT');

server.listen(port, () =>
  void 0
);
