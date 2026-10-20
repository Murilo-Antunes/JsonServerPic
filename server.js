const path = require('path');
const jsonServer = require('json-server');
const { authRoutes, requireAuth, tenantScope, stripPasswords } = require('./auth.routes');
const { dashboardRoutes } = require('./dashboard.routes');
const { productsRoutes } = require('./products.routes');

const server = jsonServer.create();
server.set('trust proxy', 1); // atrás do proxy do Render: req.ip passa a ser o IP real do cliente
const router = jsonServer.router(path.join(__dirname, 'db.json'));

// Garante que as coleções existam, mesmo num db.json novo ou incompleto.
router.db
  .defaults({ companies: [], users: [], categories: [], products: [], customers: [], sales: [], transactions: [], settings: [], notifications: [] })
  .write();

server.use(jsonServer.defaults({ bodyParser: false })); // CORS, logger, static
server.use(jsonServer.bodyParser);

authRoutes(server, router); // /auth/register, /auth/login, /auth/me
dashboardRoutes(server, router); // GET /dashboard
productsRoutes(server, router); // /products (lista, detalhe, criar, editar, excluir)

// Todo o resto (ex.: /categories) exige token e é filtrado pela empresa do usuário.
server.use(requireAuth, tenantScope(router));
stripPasswords(router);
server.use(router);

const port = process.env.PORT || 3000;
server.listen(port, () => console.log(`API em http://localhost:${port}`));
