// server.js — FIXED VERSION (Render Compatible)
"use strict";
require("dotenv").config();

const fs = require("fs");
const path = require("path");
const express = require("express");
const helmet = require("helmet");
const session = require("express-session");
const bcrypt = require("bcrypt");
const multer = require("multer");

const app = express();

// -------- ENV --------
const {
  NODE_ENV = "production",
  PORT = 3000,
  SESSION_SECRET = "change_me",
  SESSION_IDLE_MS = String(10 * 60 * 1000),
  BASE_PATH: RAW_BASE = "/"
} = process.env;

// -------- BASE PATH NORMALIZE --------
let BASE_PATH = RAW_BASE || "/";
if (!BASE_PATH.startsWith("/")) BASE_PATH = "/" + BASE_PATH;
if (BASE_PATH !== "/" && BASE_PATH.endsWith("/"))
  BASE_PATH = BASE_PATH.slice(0, -1);

// -------- REQUIRED ON RENDER --------
app.set("trust proxy", 1);

// -------- SECURITY --------
app.use(
  helmet({
    crossOriginEmbedderPolicy: false
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// -------- SESSION --------
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

// -------- USERS --------
const USERS = [
  {
    id: "u1",
    username: "hradmin",
    role: "admin",
    passwordHash: bcrypt.hashSync("HR!2026-Secure", 12)
  },
  {
    id: "u2",
    username: "admin",
    role: "admin",
    passwordHash: bcrypt.hashSync("Admin@123!", 12)
  }
];

const findUser = (u) =>
  USERS.find((x) => x.username.toLowerCase() === String(u).toLowerCase()) ||
  null;

// -------- ROUTER --------
const r = express.Router();

r.get("/session", (req, res) => {
  res.json({
    authenticated: !!req.session.user,
    user: req.session.user || null
  });
});

r.post("/login", async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password)
    return res.status(400).json({ ok: false, error: "missing_credentials" });

  const user = findUser(username);
  if (!user)
    return res.status(401).json({ ok: false, error: "invalid_credentials" });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid)
    return res.status(401).json({ ok: false, error: "invalid_credentials" });

  req.session.user = { id: user.id, username: user.username, role: user.role };
  req.session.lastActivity = Date.now();

  return res.json({ ok: true, user: req.session.user });
});

r.post("/logout", (req, res) =>
  req.session.destroy(() => res.json({ ok: true }))
);

// -------- UPLOADS --------
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const upload = multer({ dest: uploadDir });
r.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) return res.json({ ok: false, error: "no_file" });

  res.json({
    ok: true,
    file: {
      name: req.file.originalname,
      size: req.file.size
    }
  });
});

// -------- IMPORTANT: ROUTER FIRST --------
app.use(BASE_PATH, r);

// -------- NOW STATIC (MUST BE LAST!) --------
const publicDir = path.join(__dirname, "public");
app.use(BASE_PATH, express.static(publicDir));

// -------- CONFIG.JS --------
app.get(`${BASE_PATH}/config.js`, (req, res) => {
  res.type("application/javascript").send(
    `window.__BASE_PATH__ = "${BASE_PATH}";`
  );
});

// -------- ROOT ROUTE --------
app.get(BASE_PATH === "/" ? "/" : `${BASE_PATH}/`, (req, res) =>
  res.sendFile(path.join(publicDir, "index.html"))
);

// -------- START --------
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}${BASE_PATH}`);
});