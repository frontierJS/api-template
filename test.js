import { env } from '@frontierjs/backend';
import helmet from 'helmet';
import cors from 'cors';
import express from 'express';
import bodyParser from 'body-parser';
import AuthController from '$c/AuthController';
import UserController from '$c/UserController';

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
