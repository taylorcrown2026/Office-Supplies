// server.js — Render‑safe version
"use strict";
require("dotenv").config();

const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");
const express = require("express");
const helmet = require("helmet");
const session = require("express-session");
const bcrypt = require("bcrypt");
const multer = require("multer");

const app = express();

// ----- ENV -----
const {
  NODE_ENV = "production",
  PORT = 3000,
  SESSION_SECRET = "change_me",
  SESSION_IDLE_MS = String(10 * 60 * 1000),
  BASE_PATH: RAW_BASE = "/",
  SSL_KEY,
  SSL_CERT
} = process.env;

// ----- BASE PATH NORMALIZATION -----
let BASE_PATH = String(RAW_BASE || "/");
if (!BASE_PATH.startsWith("/")) BASE_PATH = "/" + BASE_PATH;
if (BASE_PATH !== "/" && BASE_PATH.endsWith("/"))
  BASE_PATH = BASE_PATH.replace(/\/+$/, "");

// ----- RENDER / PROXY FIX -----
app.set("trust proxy", 1); // REQUIRED on Render

// ----- SECURITY -----
app.use(
  helmet({
    crossOriginEmbedderPolicy: false
  })
);

// ----- REQUEST BODY -----
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ----- SESSION -----
app.use(
  session({
    name: "sid",
    secret: SESSION_SECRET,
    resave: false,
    rolling: true,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "lax",
      maxAge: Number(SESSION_IDLE_MS)
    }
  })
);

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

// ----- DEMO USERS -----
const DEMO_USER_1 = { id: "u1", username: "hradmin", role: "admin" };
const DEMO_PASS_1 = "HR!2026-Secure";
const DEMO_HASH_1 = bcrypt.hashSync(DEMO_PASS_1, 12);

const DEMO_USER_2 = { id: "u2", username: "admin", role: "admin" };
const DEMO_PASS_2 = "Admin@123!";
const DEMO_HASH_2 = bcrypt.hashSync(DEMO_PASS_2, 12);

const USERS = [
  { ...DEMO_USER_1, passwordHash: DEMO_HASH_1 },
  { ...DEMO_USER_2, passwordHash: DEMO_HASH_2 }
];

const findUser = (u) =>
  USERS.find(
    (x) => x.username.toLowerCase() === String(u || "").toLowerCase()
  ) || null;

// ----- ROUTER -----
const r = express.Router();

// ---- SESSION CHECK ----
r.get("/session", (req, res) => {
  const user = req.session.user || null;
  res.json({ authenticated: !!user, user });
});

// ---- LOGIN ----
r.post("/login", async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password)
    return res.status(400).json({ ok: false, error: "missing_credentials" });

  const user = findUser(username);
  if (!user)
    return res.status(401).json({ ok: false, error: "invalid_credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok)
    return res.status(401).json({ ok: false, error: "invalid_credentials" });

  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role
  };
  req.session.lastActivity = Date.now();

  res.json({ ok: true, user: req.session.user });
});

// ---- LOGOUT ----
r.post("/logout", (req, res) =>
  req.session.destroy(() => res.json({ ok: true }))
);

// ---- AUTH MIDDLEWARE ----
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect(
      `${BASE_PATH}/login.html?returnTo=` +
        encodeURIComponent(req.originalUrl)
    );
  }
  next();
}

// ---- UPLOADS ----
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const safe = path
      .basename(file.originalname)
      .replace(/[^a-z0-9_.-]+/gi, "_");
    const uniq =
      Date.now().toString(36) +
      "-" +
      Math.random().toString(36).slice(2, 8);
    cb(null, `${uniq}-${safe}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024 }
});

r.post("/upload", requireAuth, upload.single("file"), (req, res) => {
  if (!req.file)
    return res.status(400).json({ ok: false, error: "no_file" });

  res.json({
    ok: true,
    file: {
      name: req.file.originalname,
      size: req.file.size,
      url: `${BASE_PATH}/uploads/${req.file.filename}`
    }
  });
});

// ---- DEBUG ----
r.get("/_demo", (req, res) =>
  res.json({
    basePath: BASE_PATH,
    expectedUsers: USERS.map((u) => u.username),
    env: { NODE_ENV, SESSION_IDLE_MS }
  })
);

// ---- WHOAMI ----
r.get("/whoami", (req, res) =>
  res.json({ user: req.session.user || null })
);

// ---- STATIC ----
const publicDir = path.join(__dirname, "public");

app.use(`${BASE_PATH}/uploads`, express.static(uploadDir));
app.use(BASE_PATH, r);
app.use(BASE_PATH, express.static(publicDir));

// ---- CONFIG.JS ----
app.get(`${BASE_PATH}/config.js`, (req, res) => {
  res.type("application/javascript").send(
    `window.__BASE_PATH__=${JSON.stringify(BASE_PATH)};`
  );
});

// ---- ROOT INDEX ----
app.get(BASE_PATH === "/" ? "/" : `${BASE_PATH}/`, (req, res) =>
  res.sendFile(path.join(publicDir, "index.html"))
);

// ---- START ----
function start() {
  const startMsg = () => {
    console.log(
      `${SSL_KEY && SSL_CERT ? "HTTPS" : "HTTP"} running on port ${PORT}`
    );
    console.log("Base path:", BASE_PATH);
  };

  if (SSL_KEY && SSL_CERT) {
    const key = fs.readFileSync(SSL_KEY);
    const cert = fs.readFileSync(SSL_CERT);
    https.createServer({ key, cert }, app).listen(PORT, startMsg);
  } else {
    http.createServer(app).listen(PORT, startMsg);
  }
}

start();
