const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo-em-producao';
const JWT_EXPIRES_IN = '1h';

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

function signToken(user) {
  return jwt.sign({ sub: user.id, companyId: user.companyId, role: user.role }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });
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

  server.get('/auth/me', requireAuth, (req, res) => {
    const user = db.get('users').find({ id: req.auth.sub }).value();
    if (!user) return res.status(401).json({ message: 'Usuário não encontrado.' });
    const company = db.get('companies').find({ id: user.companyId }).value();
    res.json({ user: publicUser(user), company });
  });
}

module.exports = { authRoutes, requireAuth, tenantScope, stripPasswords, signToken };
