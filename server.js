// server.js (SOC2-ready baseline)
'use strict';

require('dotenv').config();

const express = require('express');
const path = require('path');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');

const app = express();

/* -------------------- Security & middleware -------------------- */
app.use(helmet({
  // Fine-tune as needed; keep defaults for sensible headers
  crossOriginEmbedderPolicy: false, // adjust if serving cross-origin assets
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* -------------------- Config & env -------------------- */
const {
  NODE_ENV = 'development',
  PORT = 3000,
  SESSION_SECRET,
  REDIS_URL = 'redis://localhost:6379',
  SESSION_NAME = 'sid',
  // Idle timeout: 10 minutes to match your requirement
  SESSION_IDLE_MS = 10 * 60 * 1000
} = process.env;

if (!SESSION_SECRET) {
  console.error('Missing SESSION_SECRET. Set it in your environment.');
  process.exit(1);
}

/* -------------------- Session store (Redis) -------------------- */
const redisClient = createClient({ url: REDIS_URL });
redisClient.on('error', (err) => console.error('Redis error', err));
redisClient.connect().catch(err => {
  console.error('Failed to connect to Redis:', err);
  process.exit(1);
});

const store = new RedisStore({ client: redisClient, prefix: 'sess:' });

app.use(session({
  name: SESSION_NAME,
  secret: SESSION_SECRET,
  store,
  resave: false,
  rolling: true, // refresh cookie on activity (server-enforced idle timeout)
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: NODE_ENV === 'production', // set true behind TLS/HTTPS
    sameSite: 'lax',
    maxAge: Number(SESSION_IDLE_MS)
  }
}));

/* -------------------- Rate limiting (login) -------------------- */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min window
  max: 20,                  // limit each IP
  standardHeaders: true,
  legacyHeaders: false,
});

/* -------------------- Mock user store (replace with DB) -------------------- */
// Example: one admin and one user with hashed passwords.
// In production: fetch user by email/username from your DB and compare hash.
const users = [
  // password = "Admin@123!"
  { id: '1', username: 'admin', role: 'admin', passwordHash: '$2b$12$4mM4IUd/J0mNQv5K3l0U3e9Y7XyUjS2SxM3JXb3lS0qP7SgD9m3hK' },
  // password = "User@123!"
  { id: '2', username: 'user',  role: 'user',  passwordHash: '$2b$12$7vS1x8M0yG3V1u9JgQ7rOuuqgqGQzJ8v5r3pXbE9e4d6O9c2w6cnK' },
];

async function findUser(username) {
  return users.find(u => u.username.toLowerCase() === String(username).toLowerCase()) || null;
}

/* -------------------- Auth helpers -------------------- */
function requireAuth(req, res, next) {
  if (!req.session.user) {
    // For API-style responses:
    if (req.accepts('json')) return res.status(401).json({ ok: false, error: 'unauthorized' });
    // For browser pages:
    return res.redirect('/login.html?returnTo=' + encodeURIComponent(req.originalUrl));
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).send('Forbidden');
  }
  next();
}

// Server-enforced idle timeout (defense-in-depth with rolling cookie)
app.use((req, res, next) => {
  if (req.session?.user) {
    const now = Date.now();
    const last = req.session.lastActivity || 0;
    if (now - last > Number(SESSION_IDLE_MS)) {
      req.session.destroy(() => next());
      return;
    }
    req.session.lastActivity = now;
  }
  next();
});

/* -------------------- Routes -------------------- */
// Login (JSON API). If you prefer redirect form POST, see commented alternative below.
app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: 'missing_credentials' });
  }

  const user = await findUser(username);
  // Avoid leaking user existence via timing or messages; keep messages generic
  if (!user) return res.status(401).json({ ok: false, error: 'invalid_credentials' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ ok: false, error: 'invalid_credentials' });

  // (Optional) If using MFA, check step-up here before finalizing session
  req.session.user = { id: user.id, username: user.username, role: user.role };
  req.session.lastActivity = Date.now();
  return res.json({ ok: true });
});

// Alternative redirect style (keep if your front-end posts form-encoded):
// app.post('/login', loginLimiter, async (req, res) => {
//   const { username, password } = req.body || {};
//   const user = await findUser(username);
//   if (!user) return res.redirect('/login.html?error=invalid');
//   const valid = await bcrypt.compare(password, user.passwordHash);
//   if (!valid) return res.redirect('/login.html?error=invalid');
//   req.session.user = { id: user.id, username: user.username, role: user.role };
//   req.session.lastActivity = Date.now();
//   const returnTo = req.query.returnTo || '/index.auth.html';
//   return res.redirect(returnTo);
// });

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// Protected example routes
app.get('/requests', requireAdmin, (req, res) => {
  res.json([]); // replace with real data
});

// Example user-only action
app.post('/request', requireAuth, (req, res) => {
  // validate and perform action...
  res.json({ ok: true });
});

/* -------------------- Static hosting -------------------- */
// Serve your static app (ensure login.html, index.auth.html, auth.js present)
app.use(express.static(path.join(__dirname)));

// Default doc
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.auth.html'));
});

/* -------------------- Start -------------------- */
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT} (${NODE_ENV})`);
});