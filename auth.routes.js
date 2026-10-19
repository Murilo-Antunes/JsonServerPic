/**
 * Rotas de autenticação para o json-server (referência).
 *
 *   POST /auth/register  → cria empresa + administrador e devolve o JWT
 *   GET  /auth/me        → dados da sessão a partir do token
 *
 * Também exporta `requireAuth`, `tenantScope` e `stripPasswords`, que devem
 * proteger o restante da API (veja server.js).
 */
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo-em-producao';
const JWT_EXPIRES_IN = '1h';
const JWT_EXPIRES_IN_REMEMBER = '7d'; // "Manter conectado neste dispositivo"

// Limite de tentativas de login por IP + e-mail (em memória; zera ao reiniciar o servidor).
const MAX_FAILED_LOGINS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const failedLogins = new Map(); // chave → { count, resetAt }
// Hash de mentira, para o tempo de resposta ser igual quando o e-mail não existe.
const DUMMY_HASH = bcrypt.hashSync('senha-que-nao-existe', 10);

const onlyDigits = (v) => String(v ?? '').replace(/\D/g, '');
const newId = (prefix) => `${prefix}_${crypto.randomBytes(4).toString('hex')}`;
const publicUser = ({ password, ...user }) => user;

function isValidCnpj(digits) {
  if (digits.length !== 14 || /^(\d)\1+$/.test(digits)) return false;
  const check = (length) => {
    let sum = 0;
    let weight = length - 7;
    for (let i = 0; i < length; i++) {
      sum += Number(digits[i]) * weight--;
      if (weight < 2) weight = 9;
    }
    const rest = sum % 11;
    return rest < 2 ? 0 : 11 - rest;
  };
  return check(12) === Number(digits[12]) && check(13) === Number(digits[13]);
}

const isEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(v ?? ''));
const isStrongPassword = (p) =>
  typeof p === 'string' && p.length >= 8 && /[a-z]/.test(p) && /[A-Z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p);

/** Validação de formato (a mesma que o front faz — o servidor nunca confia no front). */
function validateRegister({ company = {}, admin = {} }) {
  const errors = {};
  const need = (key, value, ok = !!String(value ?? '').trim(), message = 'Campo obrigatório.') => {
    if (!ok) errors[key] = message;
  };
  need('company.legalName', company.legalName);
  need('company.tradeName', company.tradeName);
  need('company.document', company.document, isValidCnpj(onlyDigits(company.document)), 'CNPJ inválido.');
  need('company.email', company.email, isEmail(company.email), 'E-mail inválido.');
  need('company.phone', company.phone, [10, 11].includes(onlyDigits(company.phone).length), 'Telefone inválido.');
  need('company.segment', company.segment);
  const a = company.address || {};
  for (const key of ['zipCode', 'street', 'number', 'city', 'state']) need(`company.address.${key}`, a[key]);
  need('admin.name', admin.name);
  need('admin.email', admin.email, isEmail(admin.email), 'E-mail inválido.');
  need('admin.password', admin.password, isStrongPassword(admin.password), 'Senha fraca.');
  return errors;
}

function signToken(user, expiresIn = JWT_EXPIRES_IN) {
  return jwt.sign({ sub: user.id, companyId: user.companyId, role: user.role }, JWT_SECRET, { expiresIn });
}

/** Segundos até liberar novas tentativas (0 = pode tentar). */
function lockedSeconds(key) {
  const entry = failedLogins.get(key);
  if (!entry || entry.resetAt <= Date.now()) {
    failedLogins.delete(key);
    return 0;
  }
  return entry.count >= MAX_FAILED_LOGINS ? Math.ceil((entry.resetAt - Date.now()) / 1000) : 0;
}

function recordFailedLogin(key) {
  const entry = failedLogins.get(key);
  if (!entry || entry.resetAt <= Date.now()) failedLogins.set(key, { count: 1, resetAt: Date.now() + LOGIN_WINDOW_MS });
  else entry.count += 1;
}

/** Exige `Authorization: Bearer <jwt>` e coloca o payload em `req.auth`. */
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Token ausente.' });
  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Sessão inválida ou expirada.' });
  }
}

/** Multi-empresa: cada usuário só enxerga e grava dados da própria empresa. */
function tenantScope(req, res, next) {
  const { companyId } = req.auth;
  if (req.method === 'GET') req.query.companyId = companyId;
  else if (req.body && typeof req.body === 'object') req.body.companyId = companyId;
  next();
}

/** Nunca devolve hash de senha, mesmo em GET /users. */
function stripPasswords(router) {
  router.render = (req, res) => {
    const strip = (row) => (row && typeof row === 'object' && 'password' in row ? publicUser(row) : row);
    res.jsonp(Array.isArray(res.locals.data) ? res.locals.data.map(strip) : strip(res.locals.data));
  };
}

function authRoutes(server, router) {
  const db = router.db; // lowdb 1.x

  server.post('/auth/register', (req, res) => {
    const { company = {}, admin = {} } = req.body || {};

    const errors = validateRegister(req.body || {});
    if (Object.keys(errors).length) return res.status(422).json({ message: 'Confira os dados informados.', errors });

    const taken = {};
    const document = onlyDigits(company.document);
    if (db.get('companies').find((c) => onlyDigits(c.document) === document).value()) {
      taken['company.document'] = 'Já existe uma conta com este CNPJ.';
    }
    const adminEmail = String(admin.email).trim().toLowerCase();
    if (db.get('users').find((u) => String(u.email).toLowerCase() === adminEmail).value()) {
      taken['admin.email'] = 'Este e-mail já está em uso.';
    }
    if (Object.keys(taken).length) return res.status(409).json({ message: 'Cadastro já existente.', errors: taken });

    const now = new Date().toISOString();
    const companyRow = {
      id: newId('cmp'),
      legalName: String(company.legalName).trim(),
      tradeName: String(company.tradeName).trim(),
      document: company.document,
      email: String(company.email).trim().toLowerCase(),
      phone: onlyDigits(company.phone),
      segment: company.segment,
      status: 'ACTIVE',
      address: { complement: '', ...company.address },
      createdAt: now,
      updatedAt: now,
    };
    const userRow = {
      id: newId('usr'),
      companyId: companyRow.id,
      name: String(admin.name).trim(),
      email: adminEmail,
      password: bcrypt.hashSync(admin.password, 10),
      role: 'ADMIN',
      status: 'ACTIVE',
      lastLoginAt: now,
      createdAt: now,
    };
    const settingsRow = {
      id: newId('set'),
      companyId: companyRow.id,
      userId: userRow.id,
      notifications: { sales: true, payments: true, lowStock: true, system: true, weeklyReports: false },
      appearance: { theme: 'light' },
      language: 'pt-BR',
    };

    // Tudo em memória e uma única gravação em disco: ou entra tudo, ou nada.
    db.get('companies').push(companyRow).value();
    db.get('users').push(userRow).value();
    db.get('settings').push(settingsRow).value();
    db.write();

    res.status(201).json({ accessToken: signToken(userRow), user: publicUser(userRow), company: companyRow });
  });

  server.post('/auth/login', (req, res) => {
    const { email, password, remember } = req.body || {};
    if (!isEmail(email) || typeof password !== 'string' || !password) {
      return res.status(422).json({ message: 'Informe o e-mail e a senha.' });
    }

    const normalized = String(email).trim().toLowerCase();
    const key = `${req.ip}|${normalized}`;

    const wait = lockedSeconds(key);
    if (wait) {
      res.set('Retry-After', String(wait));
      return res.status(429).json({ message: 'Muitas tentativas. Tente novamente em alguns minutos.' });
    }

    const user = db.get('users').find((u) => String(u.email).toLowerCase() === normalized).value();
    // Sempre compara com algum hash e usa a mesma mensagem: não revela se o e-mail existe.
    const passwordOk = bcrypt.compareSync(password, user ? user.password : DUMMY_HASH);
    if (!user || !passwordOk) {
      recordFailedLogin(key);
      return res.status(401).json({ message: 'E-mail ou senha incorretos.' });
    }

    const company = db.get('companies').find({ id: user.companyId }).value();
    if (user.status !== 'ACTIVE' || !company || company.status !== 'ACTIVE') {
      return res.status(403).json({ message: 'Esta conta está inativa. Fale com o suporte.' });
    }

    failedLogins.delete(key);
    const updated = db.get('users').find({ id: user.id }).assign({ lastLoginAt: new Date().toISOString() }).value();
    db.write();

    const accessToken = signToken(updated, remember ? JWT_EXPIRES_IN_REMEMBER : JWT_EXPIRES_IN);
    res.json({ accessToken, user: publicUser(updated), company });
  });

  server.get('/auth/me', requireAuth, (req, res) => {
    const user = db.get('users').find({ id: req.auth.sub }).value();
    if (!user) return res.status(401).json({ message: 'Usuário não encontrado.' });
    const company = db.get('companies').find({ id: user.companyId }).value();
    res.json({ user: publicUser(user), company });
  });
}

/**
 * GET /dashboard?period=7d|30d|90d|12m
 *
 * Calcula no servidor tudo o que o dashboard mostra (o json-server não soma,
 * agrupa nem compara períodos). Só enxerga dados da empresa do token.
 *
 * Regras:
 *  - Faturamento / vendas / ticket médio: vendas com status COMPLETED no período
 *    (estornadas e pendentes não entram). Variação % = período atual x anterior de mesmo tamanho.
 *  - Saldo disponível: soma de `transactions` liquidadas (APPROVED, COMPLETED, REFUNDED).
 *    A receber: soma das transações PENDING positivas.
 *  - Dias e meses são contados no fuso de Brasília.
 */

function addDays(key, delta) {
  const [y, m, d] = key.split('-').map(Number);
  return new Date(Date.UTC(y, m - 1, d + delta)).toISOString().slice(0, 10);
}
function addMonths(key, delta) {
  const [y, m] = key.split('-').map(Number);
  return new Date(Date.UTC(y, m - 1 + delta, 1)).toISOString().slice(0, 7);
}

/** Chaves (dias ou meses) do período atual e do período anterior, do mais antigo ao mais novo. */
function periodKeys(period, now = new Date()) {
  const monthly = period === '12m';
  const size = monthly ? 12 : parseInt(period, 10);
  const today = monthly ? monthKey(now) : dayKey(now);
  const step = monthly ? addMonths : addDays;
  const range = (offset) => Array.from({ length: size }, (_, i) => step(today, i - (size - 1) - offset));
  return { monthly, current: range(0), previous: range(size) };
}

const labelOf = (key, monthly) => (monthly ? MONTHS[Number(key.slice(5, 7)) - 1] : `${key.slice(8, 10)}/${key.slice(5, 7)}`);
const percentChange = (current, previous) => (previous > 0 ? round1(((current - previous) / previous) * 100) : null);

const PAYMENT_GROUPS = [
  { id: 'pix', label: 'Pix', methods: ['PIX'] },
  { id: 'credit', label: 'Cartão de crédito', methods: ['CREDIT_CARD'] },
  { id: 'debit', label: 'Cartão de débito', methods: ['DEBIT_CARD'] },
  { id: 'other', label: 'Outros (saldo, boleto)', methods: [] }, // todo o resto
];
const groupOf = (method) => (PAYMENT_GROUPS.find((g) => g.methods.includes(method)) || PAYMENT_GROUPS[3]).id;

/** Percentuais inteiros que sempre somam 100 (método do maior resto). */
function toShares(amounts) {
  const total = sum(amounts, (a) => a.amount);
  if (!total) return [];
  const raw = amounts.map((a) => (a.amount / total) * 100);
  const shares = raw.map(Math.floor);
  let left = 100 - sum(shares, (s) => s);
  raw
    .map((value, index) => ({ index, rest: value - Math.floor(value) }))
    .sort((a, b) => b.rest - a.rest)
    .slice(0, left)
    .forEach(({ index }) => (shares[index] += 1));
  return shares;
}

const SALE_METHODS = { PIX: 'pix', CREDIT_CARD: 'credit', DEBIT_CARD: 'debit', BALANCE: 'balance' };
const SALE_STATUSES = { COMPLETED: 'approved', PENDING: 'pending', REFUNDED: 'refunded' };
const saleCode = (id) => `VD-${String(id).replace(/^[^_]*_/, '').toUpperCase()}`;
const METHOD_LABELS = { PIX: 'Pix', CREDIT_CARD: 'Cartão de crédito', DEBIT_CARD: 'Cartão de débito', BALANCE: 'Saldo', BOLETO: 'Boleto' };

function transactionKind(t) {
  if (t.type === 'REFUND') return 'refund';
  if (t.category === 'FEE') return 'fee';
  if (t.category === 'SALE') return 'sale';
  return t.amount >= 0 ? 'income' : 'withdrawal';
}

function buildDashboard(db, companyId, period) {
  const mine = (collection) => db.get(collection).filter({ companyId }).value();
  const sales = mine('sales');
  const customers = new Map(mine('customers').map((c) => [c.id, c.name]));
  const customerName = (sale) => customers.get(sale.customerId) || 'Consumidor não identificado';
  const salesById = new Map(sales.map((s) => [s.id, s]));

  // ---- Período atual x anterior
  const { monthly, current, previous } = periodKeys(period);
  const keyOf = (sale) => (monthly ? monthKey(new Date(sale.createdAt)) : dayKey(new Date(sale.createdAt)));
  const completed = sales.filter((s) => s.status === 'COMPLETED');
  const inKeys = (keys) => {
    const set = new Set(keys);
    return completed.filter((s) => set.has(keyOf(s)));
  };
  const now = inKeys(current);
  const before = inKeys(previous);

  const revenue = round2(sum(now, (s) => s.total));
  const count = now.length;
  const ticket = count ? round2(revenue / count) : 0;
  const prevRevenue = sum(before, (s) => s.total);
  const prevTicket = before.length ? prevRevenue / before.length : 0;

  // ---- Série do gráfico (vazia quando não houve nenhuma venda no período)
  const totals = new Map();
  now.forEach((s) => totals.set(keyOf(s), (totals.get(keyOf(s)) || 0) + s.total));
  const salesSeries = count
    ? current.map((key) => ({ label: labelOf(key, monthly), value: round2(totals.get(key) || 0) }))
    : [];

  // ---- Métodos de pagamento
  const byGroup = PAYMENT_GROUPS.map((g) => ({
    ...g,
    amount: round2(sum(now.filter((s) => groupOf(s.payment?.method) === g.id), (s) => s.total)),
  })).filter((g) => g.amount > 0);
  const shares = toShares(byGroup);
  const payments = byGroup.map((g, i) => ({ id: g.id, label: g.label, share: shares[i], amount: g.amount }));

  // ---- Últimas vendas
  const latestSales = [...sales].sort(byDateDesc).slice(0, 6).map((s) => ({
    id: s.id,
    code: saleCode(s.id),
    customer: customerName(s),
    createdAt: s.createdAt,
    method: SALE_METHODS[s.payment?.method] || 'other',
    amount: s.total,
    status: SALE_STATUSES[s.status] || 'refused',
  }));

  // ---- Estoque baixo (produtos ativos no limite ou abaixo do mínimo)
  const low = mine('products')
    .filter((p) => p.status === 'ACTIVE' && p.minimumStock > 0 && p.stock <= p.minimumStock)
    .sort((a, b) => a.stock / a.minimumStock - b.stock / b.minimumStock || a.name.localeCompare(b.name));
  const lowStock = low.slice(0, 5).map((p) => ({ id: p.id, name: p.name, quantity: p.stock, minimum: p.minimumStock }));

  // ---- Saldo e últimas transações
  const ledger = mine('transactions');
  const balance = round2(sum(ledger.filter((t) => SETTLED.includes(t.status)), (t) => t.amount));
  const receivable = round2(sum(ledger.filter((t) => t.status === 'PENDING' && t.amount > 0), (t) => t.amount));

  const transactions = [...ledger].sort(byDateDesc).slice(0, 8).map((t) => {
    const kind = transactionKind(t);
    const sale = salesById.get(t.saleId);
    const who = sale ? `${saleCode(sale.id)} · ${customerName(sale)}` : '';
    const title =
      kind === 'sale' ? `Venda ${who}`
      : kind === 'refund' ? `Estorno ${who}`
      : kind === 'fee' ? `Taxa de processamento · ${METHOD_LABELS[t.paymentMethod] || ''}`.replace(/ · $/, '')
      : t.description;
    return { id: t.id, kind, title, createdAt: t.createdAt, amount: t.amount, pending: t.status === 'PENDING' };
  });

  return {
    summary: {
      balance,
      receivable,
      revenue: { value: revenue, delta: percentChange(revenue, prevRevenue) },
      salesCount: { value: count, delta: percentChange(count, before.length) },
      averageTicket: { value: ticket, delta: percentChange(ticket, prevTicket) },
    },
    salesSeries,
    payments,
    sales: latestSales,
    lowStock,
    lowStockTotal: low.length,
    transactions,
  };
}

function dashboardRoutes(server, router) {
  server.get('/dashboard', requireAuth, (req, res) => {
    const period = String(req.query.period || '30d');
    if (!PERIODS.includes(period)) {
      return res.status(400).json({ message: 'Período inválido. Use 7d, 30d, 90d ou 12m.' });
    }
    res.json(buildDashboard(router.db, req.auth.companyId, period));
  });
}

module.exports = { authRoutes, requireAuth, tenantScope, stripPasswords, signToken, dashboardRoutes, buildDashboard  };
