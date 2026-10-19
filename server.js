const path = require('path');
const jsonServer = require('json-server');
const { authRoutes, requireAuth, tenantScope, stripPasswords } = require('./auth.routes');
const { dashboardRoutes } = require('./dashboard.routes');

const server = jsonServer.create();
server.set('trust proxy', 1); // atrás do proxy do Render: req.ip passa a ser o IP real do cliente
const router = jsonServer.router(path.join(__dirname, 'db.json'));

server.use(jsonServer.defaults()); // CORS, logger, static
server.use(jsonServer.bodyParser);

authRoutes(server, router); // /auth/register, /auth/login, /auth/me
dashboardRoutes(server, router); // GET /dashboard (protegida pelo próprio handler)

// Todo o resto exige token e é filtrado pela empresa do usuário.
server.use(requireAuth, tenantScope);
stripPasswords(router);
server.use(router);

const port = process.env.PORT || 3000;
server.listen(port, () => console.log(`API em http://localhost:${port}`));
