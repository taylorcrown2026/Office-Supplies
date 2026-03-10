// server.js — working auth server (bcrypt + sessions + uploads), accepts hradmin & admin
'use strict';

require('dotenv').config();
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');

const app = express();

/* =========================
   Config (env + defaults)
========================= */
const {
  NODE_ENV = 'development',
  PORT = 3000,
  SESSION_SECRET = 'dev_only_change_me',
  SESSION_IDLE_MS = String(10 * 60 * 1000), // 10 minutes
  SSL_KEY,
  SSL_CERT,
} = process.env;

/* =========================
   Security & middlewares
========================= */
app.use(helmet({
  crossOriginEmbedderPolicy: false, // static assets only; relax for simplicity
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sessions (MemoryStore for simplicity; use Redis for production)
app.use(session({
  name: 'sid',
  secret: SESSION_SECRET,
  resave: false,
  rolling: true,                 // refresh cookie on each request
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: Number(SESSION_IDLE_MS),
  }
}));

// Enforce server-side idle timeout
app.use((req, res, next) => {
  if (req.session?.user) {
    const now = Date.now();
    const last = req.session.lastActivity || 0;
    if (now - last > Number(SESSION_IDLE_MS)) {
      return req.session.destroy(() => next());
    }
    req.session.lastActivity = now;
  }
  next();
});

/* =========================
   Demo users (bcrypt)
   - Accept BOTH 'hradmin' and 'admin'
========================= */

// hradmin / HR!2026-Secure
const DEMO_USER_1 = { id: 'u1', username: 'hradmin', role: 'admin' };
const DEMO_PASS_1 = 'HR!2026-Secure';
const DEMO_HASH_1 = bcrypt.hashSync(DEMO_PASS_1, 12);

// admin / Admin@123!
const DEMO_USER_2 = { id: 'u2', username: 'admin', role: 'admin' };
const DEMO_PASS_2 = 'Admin@123!';
const DEMO_HASH_2 = bcrypt.hashSync(DEMO_PASS_2, 12);

// Simple in-memory "user store"
const USERS = [
  { ...DEMO_USER_1, passwordHash: DEMO_HASH_1 },
  { ...DEMO_USER_2, passwordHash: DEMO_HASH_2 },
];

function findUser(username) {
  const u = String(username || '').toLowerCase();
  return USERS.find(x => x.username.toLowerCase() === u) || null;
}

/* =========================
   Auth APIs
========================= */
app.get('/session', (req, res) => {
  const user = req.session.user || null;
  res.json({ authenticated: !!user, user });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: 'missing_credentials' });
  }
  const user = findUser(username);
  if (!user) {
    if (NODE_ENV !== 'production') console.warn('Login failed (no such user):', username);
    return res.status(401).json({ ok: false, error: 'invalid_credentials' });
  }
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    if (NODE_ENV !== 'production') console.warn('Login failed (bad password):', username);
    return res.status(401).json({ ok: false, error: 'invalid_credentials' });
  }
  req.session.user = { id: user.id, username: user.username, role: user.role };
  req.session.lastActivity = Date.now();
  return res.json({ ok: true, user: req.session.user });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// Gate for any server endpoints that need auth
function requireAuth(req, res, next) {
  if (!req.session.user) {
    if (req.accepts('json')) return res.status(401).json({ ok: false, error: 'unauthorized' });
    return res.redirect('/login.html?returnTo=' + encodeURIComponent(req.originalUrl));
  }
  next();
}

/* =========================
   Uploads (for invoice.html)
========================= */
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const safeBase = path.basename(file.originalname).replace(/[^a-z0-9_.-]+/gi, '_');
    const uniq = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
    cb(null, uniq + '-' + safeBase);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024 } // 15 MB
});

app.post('/upload', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ ok: false, error: 'no_file' });
  res.json({
    ok: true,
    file: {
      name: req.file.originalname,
      size: req.file.size,
      url: '/uploads/' + req.file.filename
    }
  });
});

/* =========================
   Static hosting
========================= */
const publicDir = path.join(__dirname, 'public');
app.use('/uploads', express.static(uploadDir, { dotfiles: 'deny', maxAge: '7d' }));
app.use(express.static(publicDir));
app.get('/', (req, res) => res.sendFile(path.join(publicDir, 'index.html')));

/* =========================
   Dev info endpoint (optional)
   - Helps confirm which server is running
========================= */
app.get('/_demo', (req, res) => {
  res.json({
    expectedUsers: USERS.map(u => u.username),
    env: { NODE_ENV, SESSION_IDLE_MS: SESSION_IDLE_MS }
  });
});

/* =========================
   Start (HTTP/HTTPS)
========================= */
function start() {
  if (SSL_KEY && SSL_CERT && fs.existsSync(SSL_KEY) && fs.existsSync(SSL_CERT)) {
    const key = fs.readFileSync(SSL_KEY);
    const cert = fs.readFileSync(SSL_CERT);
    https.createServer({ key, cert }, app).listen(PORT, () => {
      console.log(`HTTPS on https://localhost:${PORT} (${NODE_ENV})`);
      console.log('Demo credentials available:');
      console.log('  • %s / %s', DEMO_USER_1.username, DEMO_PASS_1);
      console.log('  • %s / %s', DEMO_USER_2.username, DEMO_PASS_2);
    });
  } else {
    http.createServer(app).listen(PORT, () => {
      console.log(`HTTP on http://localhost:${PORT} (${NODE_ENV})`);
      console.log('Demo credentials available:');
      console.log('  • %s / %s', DEMO_USER_1.username, DEMO_PASS_1);
      console.log('  • %s / %s', DEMO_USER_2.username, DEMO_PASS_2);
      console.log('Tip: provide SSL_KEY and SSL_CERT for HTTPS in dev.');
    });
  }
}
start();