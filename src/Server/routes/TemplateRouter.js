import express from 'express'
let router = express.Router()

import bodyParser from 'body-parser'
router.use(bodyParser.urlencoded({ extended: false }))
router.use(bodyParser.json())

router.use('/', (req, res, next) => {
  // console.log({body: req.body})
  next()
})

import TemplateController from '$c/TemplateController'
import AuthController from '$c/AuthController'

router.get(
  '/',
  // AuthController.authenticateTokenMiddleware,
  TemplateController.index
)
export default router
