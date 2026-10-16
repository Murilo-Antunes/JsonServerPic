require('dotenv').config(); 

const path = require('path');
const jsonServer = require('json-server')
const server = jsonServer.create()
const router = jsonServer.router(path.join(__dirname, 'db.json'));
const { authRoutes, requireAuth, tenantScope, stripPasswords } = require('./auth.routes');

const port = process.env.PORT

authRoutes(server, router); // /auth/register, /auth/me (públicas)

// Todo o resto exige token e é filtrado pela empresa do usuário.
server.use(requireAuth, tenantScope);
stripPasswords(router);
server.use(router);

server.listen(port, () => console.log(`API em http://localhost:${port}`));