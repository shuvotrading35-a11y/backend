'use strict';

const express   = require('express');
const cors      = require('cors');
const path      = require('path');
const fs        = require('fs');
const crypto    = require('crypto');
const initSqlJs = require('sql.js');

// ──────────────────────────────────────────────
//  কনফিগ
// ──────────────────────────────────────────────
const PORT        = process.env.PORT        || 3000;
const ADMIN_USER  = process.env.ADMIN_USER  || 'admin';
const ADMIN_PASS  = process.env.ADMIN_PASS  || 'TasteAdmin2025!';
const SESSION_TTL = 24 * 60 * 60 * 1000;
const DB_PATH     = path.join(__dirname, 'data.db');

// ──────────────────────────────────────────────
//  sql.js wrapper — synchronous-style helpers
// ──────────────────────────────────────────────
let db;

function loadDb(SQL) {
  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }
}

function saveDb() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// run: INSERT / UPDATE / DELETE / CREATE
function run(sql, params = []) {
  db.run(sql, params);
  saveDb();
}

// get: একটি row ফেরত দেয়
function get(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return undefined;
}

// all: সব row ফেরত দেয়
function all(sql, params = []) {
  const result = db.exec(sql, params);
  if (!result.length) return [];
  const { columns, values } = result[0];
  return values.map(row =>
    Object.fromEntries(columns.map((c, i) => [c, row[i]]))
  );
}

// ──────────────────────────────────────────────
//  DB Init — টেবিল তৈরি
// ──────────────────────────────────────────────
function initDb() {
  db.run(`CREATE TABLE IF NOT EXISTS submissions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    food_name   TEXT NOT NULL,
    district    TEXT NOT NULL,
    district_id TEXT,
    area        TEXT NOT NULL,
    category    TEXT NOT NULL,
    map_link    TEXT,
    description TEXT NOT NULL,
    where_to    TEXT NOT NULL,
    price       TEXT NOT NULL,
    best_time   TEXT NOT NULL,
    nearby      TEXT NOT NULL,
    user_name   TEXT NOT NULL,
    user_phone  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now','localtime')),
    reviewed_at TEXT,
    note        TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now','localtime')),
    expires_at  INTEGER NOT NULL
  )`);

  saveDb();
}

// ──────────────────────────────────────────────
//  Helpers
// ──────────────────────────────────────────────
function sanitize(val, max = 500) {
  if (typeof val !== 'string') return '';
  return val.replace(/[\x00-\x1F\x7F]/g, '').trim().slice(0, max);
}

function authMiddleware(req, res, next) {
  const auth  = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'লগইন করুন' });

  const row = get(
    'SELECT token FROM sessions WHERE token=? AND expires_at>?',
    [token, Date.now()]
  );
  if (!row) return res.status(401).json({ error: 'সেশন মেয়াদ উত্তীর্ণ। আবার লগইন করুন।' });
  next();
}

function nowStr() {
  return new Date().toLocaleString('sv').replace('T', ' ');
}

// ──────────────────────────────────────────────
//  Express
// ──────────────────────────────────────────────
const app = express();

app.use(cors({ origin: '*', methods: ['GET','POST','PUT','PATCH','DELETE'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// ──────────────────────────────────────────────
//  PUBLIC ROUTES
// ──────────────────────────────────────────────

app.post('/api/submissions', (req, res) => {
  const b = req.body || {};
  const required = ['foodName','district','area','category','description','whereToFind','price','bestTime','nearby','userName','userPhone'];
  for (const f of required) {
    if (!b[f] || !String(b[f]).trim())
      return res.status(400).json({ error: `"${f}" মাঠটি পূরণ করুন।` });
  }
  if (sanitize(b.description, 2000).length < 30)
    return res.status(400).json({ error: 'বিবরণ কমপক্ষে ৩০ অক্ষর হতে হবে।' });

  run(`INSERT INTO submissions
    (food_name,district,district_id,area,category,map_link,description,where_to,price,best_time,nearby,user_name,user_phone,created_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [
      sanitize(b.foodName), sanitize(b.district), sanitize(b.districtId||''),
      sanitize(b.area), sanitize(b.category), sanitize(b.mapLink||'',500),
      sanitize(b.description,2000), sanitize(b.whereToFind,1000),
      sanitize(b.price), sanitize(b.bestTime), sanitize(b.nearby),
      sanitize(b.userName), sanitize(b.userPhone), nowStr()
    ]
  );

  const newRow = get('SELECT id FROM submissions ORDER BY id DESC LIMIT 1');
  res.status(201).json({ success: true, id: newRow?.id });
});

app.get('/api/submissions/count', (_req, res) => {
  const row = get("SELECT COUNT(*) as n FROM submissions WHERE status='pending'");
  res.json({ pending: row?.n || 0 });
});

// ──────────────────────────────────────────────
//  ADMIN ROUTES
// ──────────────────────────────────────────────

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USER || password !== ADMIN_PASS)
    return res.status(401).json({ error: 'ব্যবহারকারীর নাম বা পাসওয়ার্ড ভুল।' });

  run('DELETE FROM sessions WHERE expires_at<?', [Date.now()]);
  const token     = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + SESSION_TTL;
  run('INSERT INTO sessions (token,expires_at,created_at) VALUES (?,?,?)', [token, expiresAt, nowStr()]);
  res.json({ token });
});

app.post('/api/admin/logout', authMiddleware, (req, res) => {
  const token = (req.headers.authorization || '').slice(7);
  run('DELETE FROM sessions WHERE token=?', [token]);
  res.json({ success: true });
});

app.get('/api/admin/submissions', authMiddleware, (req, res) => {
  const status = ['pending','approved','rejected','all'].includes(req.query.status)
    ? req.query.status : 'pending';
  const page   = Math.max(1, parseInt(req.query.page) || 1);
  const limit  = 20;
  const offset = (page - 1) * limit;
  const q      = sanitize(req.query.q || '', 100);

  const where  = status === 'all' ? "1=1" : `status='${status}'`;
  const params = [];
  let search   = '';
  if (q) {
    search = ` AND (food_name LIKE ? OR district LIKE ? OR user_name LIKE ?)`;
    params.push(`%${q}%`, `%${q}%`, `%${q}%`);
  }

  const rows  = all(`SELECT * FROM submissions WHERE ${where}${search} ORDER BY created_at DESC LIMIT ? OFFSET ?`, [...params, limit, offset]);
  const total = get(`SELECT COUNT(*) as n FROM submissions WHERE ${where}${search}`, params)?.n || 0;
  const countRows = all('SELECT status, COUNT(*) as n FROM submissions GROUP BY status');
  const counts = Object.fromEntries(countRows.map(r => [r.status, r.n]));

  res.json({ rows, total, page, pages: Math.ceil(total / limit), counts });
});

app.get('/api/admin/submissions/:id', authMiddleware, (req, res) => {
  const row = get('SELECT * FROM submissions WHERE id=?', [req.params.id]);
  if (!row) return res.status(404).json({ error: 'পাওয়া যায়নি।' });
  res.json(row);
});

app.patch('/api/admin/submissions/:id', authMiddleware, (req, res) => {
  const { status, note } = req.body || {};
  if (!['approved','rejected','pending'].includes(status))
    return res.status(400).json({ error: 'অবৈধ স্ট্যাটাস।' });

  const existing = get('SELECT id FROM submissions WHERE id=?', [req.params.id]);
  if (!existing) return res.status(404).json({ error: 'পাওয়া যায়নি।' });

  run('UPDATE submissions SET status=?, note=?, reviewed_at=? WHERE id=?',
    [status, sanitize(note||'',500), nowStr(), req.params.id]);
  res.json({ success: true });
});

app.delete('/api/admin/submissions/:id', authMiddleware, (req, res) => {
  const existing = get('SELECT id FROM submissions WHERE id=?', [req.params.id]);
  if (!existing) return res.status(404).json({ error: 'পাওয়া যায়নি।' });
  run('DELETE FROM submissions WHERE id=?', [req.params.id]);
  res.json({ success: true });
});

app.get('/api/admin/export', authMiddleware, (req, res) => {
  const status = req.query.status || 'approved';
  const rows   = status === 'all'
    ? all('SELECT * FROM submissions ORDER BY created_at DESC')
    : all('SELECT * FROM submissions WHERE status=? ORDER BY created_at DESC', [status]);

  const headers = ['id','food_name','district','area','category','description','where_to','price','best_time','nearby','user_name','created_at','status','note'];
  const csv = [
    headers.join(','),
    ...rows.map(r => headers.map(h => `"${String(r[h]||'').replace(/"/g,'""')}"`).join(','))
  ].join('\n');

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="submissions_${status}_${Date.now()}.csv"`);
  res.send('\uFEFF' + csv);
});

app.get('/api/admin/stats', authMiddleware, (req, res) => {
  const total      = get('SELECT COUNT(*) as n FROM submissions')?.n || 0;
  const pending    = get("SELECT COUNT(*) as n FROM submissions WHERE status='pending'")?.n || 0;
  const approved   = get("SELECT COUNT(*) as n FROM submissions WHERE status='approved'")?.n || 0;
  const rejected   = get("SELECT COUNT(*) as n FROM submissions WHERE status='rejected'")?.n || 0;
  const todayStr   = new Date().toISOString().slice(0,10);
  const today      = get(`SELECT COUNT(*) as n FROM submissions WHERE created_at LIKE '${todayStr}%'`)?.n || 0;
  const byDistrict = all('SELECT district, COUNT(*) as n FROM submissions GROUP BY district ORDER BY n DESC LIMIT 10');
  res.json({ total, pending, approved, rejected, today, byDistrict });
});

app.get('/admin', (_req, res) =>
  res.sendFile(path.join(__dirname, '..', 'public', 'admin.html')));
app.get('/admin/*', (_req, res) =>
  res.sendFile(path.join(__dirname, '..', 'public', 'admin.html')));

app.use((_req, res) => res.status(404).json({ error: 'পাওয়া যায়নি' }));

// ──────────────────────────────────────────────
//  Start
// ──────────────────────────────────────────────
initSqlJs().then(SQL => {
  loadDb(SQL);
  initDb();
  app.listen(PORT, () => {
    console.log(`✅  চালু আছে → http://localhost:${PORT}`);
    console.log(`🔐  Admin   → http://localhost:${PORT}/admin`);
    console.log(`👤  User: ${ADMIN_USER}  |  Pass: ${ADMIN_PASS}`);
  });
}).catch(err => {
  console.error('Database লোড ব্যর্থ:', err);
  process.exit(1);
});
