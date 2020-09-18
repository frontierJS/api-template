import { env } from '@frontierjs/backend'
import helmet from 'helmet'
import cors from 'cors'

import express from 'express'
let server = express()
import router from './router.js'

server.use(cors())
server.use(helmet())
server.use(helmet.hidePoweredBy({ setTo: 'PHP 3.3.0' }))
server.use('/api/v1', router)

export default server
