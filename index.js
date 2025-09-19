require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const path = require('path');

const app = express();
const db = new Database(path.join(__dirname, 'data.db'));
// Note: The API client will be constructed per-request using a selected key
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "";
const DEFAULT_SYSTEM_INSTRUCTION = process.env.DEFAULT_SYSTEM_INSTRUCTION || "";

// Schema
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  custom_instruction TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS usage_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  model TEXT NOT NULL,
  prompt_chars INTEGER NOT NULL,
  output_chars INTEGER NOT NULL,
  tokens_est REAL NOT NULL,
  cost_est REAL NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`);

// Add missing columns defensively (for upgrades)
function ensureColumn(tableName, columnName, columnDef) {
  try {
    const cols = db.prepare(`PRAGMA table_info(${tableName})`).all();
    const has = cols.some((c) => c.name === columnName);
    if (!has) {
      db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnDef}`);
    }
  } catch (e) {
    console.error("Failed to ensure column", tableName, columnName, e);
  }
}
ensureColumn("users", "custom_instruction", "TEXT");

// Simple key/value settings helpers
function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : undefined;
}
function setSetting(key, value) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key, value);
}

// Initialize global system instruction from env once if empty
try {
  const existing = getSetting('global_system_instruction');
  if ((existing === undefined || existing === null) && DEFAULT_SYSTEM_INSTRUCTION) {
    setSetting('global_system_instruction', DEFAULT_SYSTEM_INSTRUCTION);
  }
} catch (e) {
  console.error('Failed to initialize global_system_instruction', e);
}

// API key selection helpers (round-robin stored in settings)
function listEnabledKeys() {
  return db.prepare('SELECT id, key FROM api_keys WHERE enabled = 1 ORDER BY id ASC').all();
}
function getRoundRobinIndex() {
  const v = getSetting('api_key_rr_index');
  return v ? Number(v) : 0;
}
function setRoundRobinIndex(i) {
  setSetting('api_key_rr_index', String(i));
}
function selectApiKey() {
  const rows = listEnabledKeys();
  if (!rows.length) {
    const envKey = process.env.GEMINI_API_KEY;
    if (!envKey) throw new Error('No API key available');
    return envKey;
  }
  let idx = getRoundRobinIndex();
  const key = rows[idx % rows.length].key;
  setRoundRobinIndex((idx + 1) % rows.length);
  return key;
}
function getGenAI() {
  const key = selectApiKey();
  return new GoogleGenerativeAI(key);
}

app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));

// static client
// Simple IP ban store
const bannedIps = new Map(); // ip -> expiresMs
function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || req.connection.remoteAddress || '').toString();
}
function banMiddleware(req, res, next) {
  const ip = getClientIp(req);
  const now = Date.now();
  const exp = bannedIps.get(ip);
  if (exp && exp > now) {
    return res.status(403).json({ error: 'IP temporarily banned. Try again later.' });
  }
  if (exp && exp <= now) bannedIps.delete(ip);
  next();
}

app.use(banMiddleware);

// Redirect root to auth
app.get('/', (req, res) => {
  res.redirect('/auth.html');
});

// Protect main chat page: ban IP 5 minutes if direct access without auth
app.get('/NHTAI.html', (req, res, next) => {
  const ip = getClientIp(req);
  try {
    const token = req.cookies.token;
    if (!token) throw new Error('no token');
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    bannedIps.set(ip, Date.now() + 5 * 60 * 1000);
    return res.status(403).send('Forbidden. Your IP is temporarily banned for 5 minutes.');
  }
});

app.use(express.static(path.join(__dirname, 'public')));

function setAuthCookie(res, token) {
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

function authRequired(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  next();
}

// Auth
app.post('/api/auth/register', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  const hash = await bcrypt.hash(password, 10);
  try {
    const role = ADMIN_EMAIL && email.toLowerCase() === ADMIN_EMAIL.toLowerCase() ? 'admin' : 'user';
    const stmt = db.prepare('INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)');
    const info = stmt.run(email, hash, role);
    const token = jwt.sign({ id: info.lastInsertRowid, email, role }, JWT_SECRET);
    setAuthCookie(res, token);
    res.json({ ok: true });
  } catch (e) {
    res.status(409).json({ error: 'Email already exists' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET);
  setAuthCookie(res, token);
  res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', authRequired, (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, role: req.user.role });
});

// Chat proxy (stream)
app.post('/api/chat/stream', authRequired, async (req, res) => {
  const { message, model = 'gemini-1.5-flash' } = req.body || {};
  if (!message) return res.status(400).json({ error: 'Missing message' });

  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Transfer-Encoding', 'chunked');

  try {
    const userRow = db.prepare('SELECT custom_instruction FROM users WHERE id = ?').get(req.user.id);
    const globalInstruction = getSetting('global_system_instruction') || '';
    const pieces = [];
    if (globalInstruction && globalInstruction.trim()) pieces.push(globalInstruction.trim());
    if (userRow?.custom_instruction && userRow.custom_instruction.trim()) pieces.push(userRow.custom_instruction.trim());
    const systemInstruction = pieces.length ? pieces.join('\n\n') : undefined;
    const m = getGenAI().getGenerativeModel({ model, systemInstruction });
    const result = await m.generateContentStream({ contents: [{ role: 'user', parts: [{ text: message }]}] });

    let out = '';
    for await (const chunk of result.stream) {
      const text = chunk.text();
      if (text) { out += text; res.write(text); }
    }
    await result.response;

    const promptChars = message.length;
    const outputChars = out.length;
    const tokensEst = (promptChars + outputChars) / 4;
    const costEst = 0;

    db.prepare(`
      INSERT INTO usage_logs (user_id, model, prompt_chars, output_chars, tokens_est, cost_est)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(req.user.id, model, promptChars, outputChars, tokensEst, costEst);

    res.end();
  } catch (e) {
    console.error(e);
    res.status(500).end('[Error]');
  }
});

// User custom instruction endpoints
app.get('/api/user/instruction', authRequired, (req, res) => {
  const row = db.prepare('SELECT custom_instruction FROM users WHERE id = ?').get(req.user.id);
  res.json({ customInstruction: row?.custom_instruction || '' });
});

app.post('/api/user/instruction', authRequired, (req, res) => {
  const { customInstruction } = req.body || {};
  const text = (customInstruction || '').toString();
  db.prepare('UPDATE users SET custom_instruction = ? WHERE id = ?').run(text, req.user.id);
  res.json({ ok: true });
});

// Admin
app.get('/api/admin/top-users', authRequired, adminOnly, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.email,
           COUNT(l.id) AS requests,
           SUM(l.tokens_est) AS tokens,
           SUM(l.cost_est) AS cost
    FROM users u
    LEFT JOIN usage_logs l ON l.user_id = u.id
    GROUP BY u.id
    ORDER BY tokens DESC
    LIMIT 50
  `).all();
  res.json(rows);
});

app.get('/api/admin/usage', authRequired, adminOnly, (req, res) => {
  const limit = Math.min(Number(req.query.limit || 100), 500);
  const rows = db.prepare(`
    SELECT l.*, u.email
    FROM usage_logs l
    JOIN users u ON u.id = l.user_id
    ORDER BY l.created_at DESC
    LIMIT ?
  `).all(limit);
  res.json(rows);
});

app.post('/api/admin/promote', authRequired, adminOnly, (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Missing email' });
  db.prepare('UPDATE users SET role = "admin" WHERE email = ?').run(email);
  res.json({ ok: true });
});

// Admin: global system instruction get/set
app.get('/api/admin/settings/global-instruction', authRequired, adminOnly, (req, res) => {
  const val = getSetting('global_system_instruction') || '';
  res.json({ globalInstruction: val });
});

app.post('/api/admin/settings/global-instruction', authRequired, adminOnly, (req, res) => {
  const { globalInstruction } = req.body || {};
  setSetting('global_system_instruction', (globalInstruction || '').toString());
  res.json({ ok: true });
});

// Admin: API keys management (max 10)
app.get('/api/admin/api-keys', authRequired, adminOnly, (req, res) => {
  const rows = db.prepare('SELECT id, substr(key,1,6)||"…" as preview, enabled, created_at FROM api_keys ORDER BY id ASC').all();
  const count = db.prepare('SELECT COUNT(*) AS c FROM api_keys').get().c;
  res.json({ count, keys: rows });
});

app.post('/api/admin/api-keys', authRequired, adminOnly, (req, res) => {
  try {
    const { keys } = req.body || {};
    console.log('API keys request:', { keysCount: keys?.length, keys: keys?.map(k => k?.substring(0, 6) + '...') });
    
    if (!Array.isArray(keys)) return res.status(400).json({ error: 'keys must be an array' });
    const trimmed = keys.map(k => (k||'').toString().trim()).filter(Boolean);
    if (!trimmed.length) return res.status(400).json({ error: 'no keys provided' });
    
    // Basic validation for Gemini API key format
    const invalidKeys = trimmed.filter(k => !k.startsWith('AIza') || k.length < 20);
    if (invalidKeys.length > 0) {
      return res.status(400).json({ error: 'Invalid API key format. Keys should start with "AIza" and be at least 20 characters.' });
    }
    
    const current = db.prepare('SELECT COUNT(*) AS c FROM api_keys').get().c;
    if (current + trimmed.length > 10) return res.status(400).json({ error: 'exceeds max of 10 keys' });
    
    const insert = db.prepare('INSERT INTO api_keys (key, enabled) VALUES (?, 1)');
    const tx = db.transaction((arr) => { 
      for (const k of arr) {
        try {
          insert.run(k);
        } catch (e) {
          console.error('Failed to insert key:', e);
          throw e;
        }
      }
    });
    tx(trimmed);
    console.log('Successfully added', trimmed.length, 'API keys');
    res.json({ ok: true, added: trimmed.length });
  } catch (e) {
    console.error('API keys error:', e);
    res.status(500).json({ error: 'Internal server error: ' + e.message });
  }
});

app.delete('/api/admin/api-keys/:id', authRequired, adminOnly, (req, res) => {
  const id = Number(req.params.id);
  db.prepare('DELETE FROM api_keys WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.post('/api/admin/api-keys/:id/toggle', authRequired, adminOnly, (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare('SELECT enabled FROM api_keys WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ error: 'not found' });
  const newVal = row.enabled ? 0 : 1;
  db.prepare('UPDATE api_keys SET enabled = ? WHERE id = ?').run(newVal, id);
  res.json({ ok: true, enabled: !!newVal });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});


