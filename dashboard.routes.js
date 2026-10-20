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
const { requireAuth } = require('./auth.routes');
const { stockStatus } = require('./stock');

const TZ = 'America/Sao_Paulo';
const MONTHS = ['jan', 'fev', 'mar', 'abr', 'mai', 'jun', 'jul', 'ago', 'set', 'out', 'nov', 'dez'];
const PERIODS = ['7d', '30d', '90d', '12m'];
const SETTLED = ['APPROVED', 'COMPLETED', 'REFUNDED'];

const dayFormatter = new Intl.DateTimeFormat('en-CA', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit' });
const dayKey = (date) => dayFormatter.format(date); // 'AAAA-MM-DD' em Brasília
const monthKey = (date) => dayKey(date).slice(0, 7); // 'AAAA-MM'

const round2 = (n) => Math.round(n * 100) / 100;
const round1 = (n) => Math.round(n * 10) / 10;
const sum = (rows, pick) => rows.reduce((total, row) => total + pick(row), 0);
const byDateDesc = (a, b) => (a.createdAt < b.createdAt ? 1 : -1);

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

  // ---- Estoque baixo (produtos ativos no limite, abaixo do mínimo ou zerados — mesmo critério da tela de produtos)
  const low = mine('products')
    .filter((p) => p.status === 'ACTIVE' && stockStatus(p) !== 'ok')
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

module.exports = { dashboardRoutes, buildDashboard };
