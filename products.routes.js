/**
 * Produtos da empresa do token.
 *
 *   GET    /products        lista com busca, filtros, ordenação e paginação
 *   GET    /products/:id    detalhe
 *   POST   /products        cria (SKU único por empresa)
 *   PATCH  /products/:id    edita (também aceita PUT)
 *   DELETE /products/:id    exclui (409 se o produto já foi vendido)
 *
 * Erros de validação: 422 { message, errors: { campo: 'mensagem' } }.
 * SKU repetido: 409 com o mesmo formato.
 */
const crypto = require('crypto');
const { requireAuth } = require('./auth.routes');
const { stockStatus } = require('./stock');

const STATUSES = ['ACTIVE', 'INACTIVE', 'DRAFT'];
const STOCK_FILTERS = ['ok', 'limit', 'below', 'out', 'low']; // low = limit + below + out
const PRICE_RANGES = { '0-10': [0, 10], '10-25': [10, 25], '25-50': [25, 50], '50-100': [50, 100], '100+': [100, Infinity] };
const MAX_IMAGE_CHARS = 400000; // ~300 KB em base64 (a tela já reduz a imagem antes de enviar)

const norm = (text) => String(text ?? '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
const stamp = (p) => p.updatedAt || p.createdAt || '';
const byName = (a, b) => a.name.localeCompare(b.name, 'pt-BR');

const SORTS = {
  recent: (a, b) => stamp(b).localeCompare(stamp(a)),
  oldest: (a, b) => stamp(a).localeCompare(stamp(b)),
  name_asc: byName,
  name_desc: (a, b) => byName(b, a),
  price_asc: (a, b) => a.price - b.price || byName(a, b),
  price_desc: (a, b) => b.price - a.price || byName(a, b),
  stock_asc: (a, b) => a.stock - b.stock || byName(a, b),
  stock_desc: (a, b) => b.stock - a.stock || byName(a, b),
};

function decorate(db, companyId, rows) {
  const categories = new Map(db.get('categories').filter({ companyId }).value().map((c) => [c.id, c.name]));
  return rows.map((p) => ({ ...p, categoryName: categories.get(p.categoryId) || 'Sem categoria', stockStatus: stockStatus(p) }));
}

const toListItem = (p) => ({
  id: p.id, name: p.name, sku: p.sku, categoryId: p.categoryId, categoryName: p.categoryName,
  price: p.price, cost: p.cost, stock: p.stock, minimumStock: p.minimumStock,
  status: p.status, stockStatus: p.stockStatus, updatedAt: stamp(p), hasImage: !!p.imageUrl,
});

function listProducts(db, companyId, query) {
  const all = decorate(db, companyId, db.get('products').filter({ companyId }).value());
  const search = norm(query.search).trim();

  let rows = all.filter((p) => {
    if (search && !norm(p.name).includes(search) && !norm(p.sku).includes(search)) return false;
    if (query.categoryId && p.categoryId !== query.categoryId) return false;
    if (query.status && p.status !== query.status) return false;
    if (query.stock === 'low' && p.stockStatus === 'ok') return false;
    if (query.stock && query.stock !== 'low' && p.stockStatus !== query.stock) return false;
    const range = PRICE_RANGES[query.price];
    if (range && !(p.price >= range[0] && p.price < range[1])) return false;
    return true;
  });

  rows = rows.sort(SORTS[query.sort] || SORTS.recent);

  const pageSize = Math.min(50, Math.max(1, parseInt(query.pageSize, 10) || 10));
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  const page = Math.min(pages, Math.max(1, parseInt(query.page, 10) || 1));

  return {
    items: rows.slice((page - 1) * pageSize, page * pageSize).map(toListItem),
    total: rows.length,
    page,
    pageSize,
    catalogTotal: all.length,
    lowStockCount: all.filter((p) => p.status === 'ACTIVE' && p.stockStatus !== 'ok').length,
  };
}

/** Validação de formato. Com `partial`, só confere os campos enviados (PATCH). */
function validate(body, { partial = false } = {}) {
  const errors = {};
  const check = (key, fn) => {
    if (partial && body[key] === undefined) return;
    const message = fn(body[key]);
    if (message) errors[key] = message;
  };
  const money = (v) => typeof v === 'number' && Number.isFinite(v) && v <= 1000000 && Math.round(v * 100) / 100 === v;
  const count = (v) => Number.isInteger(v) && v >= 0 && v <= 1000000;

  check('name', (v) => { const t = String(v ?? '').trim(); return t.length < 2 || t.length > 120 ? 'Informe o nome (2 a 120 caracteres).' : ''; });
  check('sku', (v) => (/^[A-Z0-9][A-Z0-9._-]{1,31}$/.test(String(v ?? '').trim().toUpperCase()) ? '' : 'SKU inválido: use 2 a 32 letras, números, ponto, hífen ou sublinhado.'));
  check('categoryId', (v) => (v && typeof v === 'string' ? '' : 'Selecione uma categoria.'));
  check('description', (v) => (v === undefined || v === null || String(v).length <= 400 ? '' : 'A descrição pode ter até 400 caracteres.'));
  check('price', (v) => (money(v) && v > 0 ? '' : 'Informe um preço maior que zero.'));
  check('cost', (v) => (money(v) && v >= 0 ? '' : 'Informe o custo (pode ser zero).'));
  check('stock', (v) => (count(v) ? '' : 'O estoque deve ser um número inteiro, zero ou maior.'));
  check('minimumStock', (v) => (count(v) ? '' : 'O estoque mínimo deve ser um número inteiro, zero ou maior.'));
  check('status', (v) => (STATUSES.includes(v) ? '' : 'Status inválido.'));
  check('imageUrl', (v) => {
    if (v === undefined || v === null || v === '') return '';
    if (typeof v !== 'string') return 'Imagem inválida.';
    if (/^data:image\/(jpeg|png);base64,/.test(v)) return v.length <= MAX_IMAGE_CHARS ? '' : 'A imagem é grande demais.';
    return /^(https?:\/\/|\/)/.test(v) ? '' : 'Imagem inválida.';
  });
  return errors;
}

const fail = (res, status, message, errors) => res.status(status).json({ message, errors });

function productsRoutes(server, router) {
  const db = router.db;
  const find = (req) => db.get('products').find({ id: req.params.id, companyId: req.auth.companyId }).value();
  const detail = (req, product) => decorate(db, req.auth.companyId, [product])[0];

  const categoryError = (companyId, categoryId) =>
    db.get('categories').find({ id: categoryId, companyId }).value() ? null : { categoryId: 'Categoria inválida.' };
  const skuError = (companyId, sku, ignoreId) =>
    db.get('products').find((p) => p.companyId === companyId && p.id !== ignoreId && String(p.sku).toUpperCase() === sku).value()
      ? { sku: 'Já existe um produto com este SKU.' } : null;

  server.get('/products', requireAuth, (req, res) => res.json(listProducts(db, req.auth.companyId, req.query)));

  server.get('/products/:id', requireAuth, (req, res) => {
    const product = find(req);
    return product ? res.json(detail(req, product)) : fail(res, 404, 'Produto não encontrado.');
  });

  server.post('/products', requireAuth, (req, res) => {
    const body = req.body || {};
    const { companyId } = req.auth;

    const errors = validate(body);
    if (Object.keys(errors).length) return fail(res, 422, 'Confira os dados do produto.', errors);

    const sku = String(body.sku).trim().toUpperCase();
    const conflict = categoryError(companyId, body.categoryId) || skuError(companyId, sku);
    if (conflict) return fail(res, categoryError(companyId, body.categoryId) ? 422 : 409, 'Confira os dados do produto.', conflict);

    const now = new Date().toISOString();
    const product = {
      id: `prd_${crypto.randomBytes(4).toString('hex')}`, companyId,
      categoryId: body.categoryId, name: String(body.name).trim(), sku,
      description: String(body.description ?? '').trim(),
      price: body.price, cost: body.cost, stock: body.stock, minimumStock: body.minimumStock,
      status: body.status, imageUrl: body.imageUrl || '', createdAt: now, updatedAt: now,
    };
    db.get('products').push(product).value();
    db.write();
    res.status(201).json(detail(req, product));
  });

  const update = (req, res) => {
    const current = find(req);
    if (!current) return fail(res, 404, 'Produto não encontrado.');

    const body = req.body || {};
    const errors = validate(body, { partial: true });
    if (Object.keys(errors).length) return fail(res, 422, 'Confira os dados do produto.', errors);

    const sku = body.sku !== undefined ? String(body.sku).trim().toUpperCase() : current.sku;
    const bad = (body.categoryId !== undefined && categoryError(req.auth.companyId, body.categoryId));
    if (bad) return fail(res, 422, 'Confira os dados do produto.', bad);
    const dup = body.sku !== undefined && skuError(req.auth.companyId, sku, current.id);
    if (dup) return fail(res, 409, 'Confira os dados do produto.', dup);

    const allowed = ['categoryId', 'name', 'description', 'price', 'cost', 'stock', 'minimumStock', 'status', 'imageUrl'];
    const patch = Object.fromEntries(allowed.filter((k) => body[k] !== undefined).map((k) => [k, typeof body[k] === 'string' ? body[k].trim() : body[k]]));
    if (patch.imageUrl !== undefined) patch.imageUrl = body.imageUrl || '';
    const updated = db.get('products').find({ id: current.id }).assign({ ...patch, sku, updatedAt: new Date().toISOString() }).value();
    db.write();
    res.json(detail(req, updated));
  };
  server.patch('/products/:id', requireAuth, update);
  server.put('/products/:id', requireAuth, update);

  server.delete('/products/:id', requireAuth, (req, res) => {
    const product = find(req);
    if (!product) return fail(res, 404, 'Produto não encontrado.');

    const sold = db.get('sales').filter({ companyId: req.auth.companyId }).value()
      .some((sale) => (sale.items || []).some((item) => item.productId === product.id));
    if (sold) return fail(res, 409, 'Este produto já tem vendas e não pode ser excluído. Inative-o para tirá-lo de circulação.');

    db.get('products').remove({ id: product.id }).value();
    db.write();
    res.status(204).end();
  });
}

module.exports = { productsRoutes, validate };
