import { env } from '@frontierjs/backend'

let port = env.get('PORT')

import server from './Server/server.js'

server.listen(port, () =>
  console.log(`
  Server listening on port ${port}!
`)
)
