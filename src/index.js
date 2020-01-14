require('frontier/lib/require')
const { env } = require('frontier')
let port = env.get('PORT') || 3000;
let server = require('./Server/server')
server.listen(port, () => console.log(`Admin Server listening on port ${port}!`))