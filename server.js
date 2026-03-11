// server.js — Web Service (Express) with auth, role protection, JSON storage
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
if (BASE_PATH !== "/" && BASE_PATH.endsWith("/")) BASE_PATH = BASE_PATH.slice(0, -1);

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

// Idle timeout refresh
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

// -------- USERS (add one regular user as requested) --------
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
  },
  {
    id: "u3",
    username: "employee",
    role: "user",
    passwordHash: bcrypt.hashSync("Employee123!", 12)
  }
];
const findUser = (u) =>
  USERS.find((x) => x.username.toLowerCase() === String(u).toLowerCase()) || null;

// -------- ROUTER (APIs) --------
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
  if (!user) return res.status(401).json({ ok: false, error: "invalid_credentials" });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(401).json({ ok: false, error: "invalid_credentials" });

  req.session.user = { id: user.id, username: user.username, role: user.role };
  req.session.lastActivity = Date.now();
  return res.json({ ok: true, user: req.session.user });
});

r.post("/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));

// -------- UPLOADS --------
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({ dest: uploadDir });

r.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) return res.json({ ok: false, error: "no_file" });
  // Not exposing public links; only store name/size.
  res.json({ ok: true, file: { name: req.file.originalname, size: req.file.size } });
});

// -------- DATA STORAGE (JSON) --------
const DATA_DIR = path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const INVOICE_DB = path.join(DATA_DIR, "invoices.json");
const SUPPLY_DB = path.join(DATA_DIR, "supplies.json");

function loadDB(file) {
  try {
    if (!fs.existsSync(file)) return [];
    return JSON.parse(fs.readFileSync(file, "utf-8"));
  } catch (e) {
    return [];
  }
}
function writeJSONAtomic(file, data) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, file);
}
function saveDB(file, data) {
  if (!Array.isArray(data)) data = [];
  writeJSONAtomic(file, data);
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "admin_only" });
  }
  next();
}

// --- Public APIs to record submissions ---
r.post("/api/invoices", (req, res) => {
  const { name, vendor, dept, file } = req.body || {};
  if (!name || !vendor || !dept)
    return res.status(400).json({ ok: false, error: "missing_fields" });

  const invoices = loadDB(INVOICE_DB);
  const item = {
    id: "inv-" + Date.now(),
    name: String(name).trim(),
    vendor: String(vendor).trim(),
    dept: String(dept).trim(),
    file: file ? String(file).trim() : null,
    completed: false,
    submittedAt: new Date().toISOString()
  };
  invoices.push(item);
  saveDB(INVOICE_DB, invoices);
  res.json({ ok: true, id: item.id });
});

r.post("/api/supplies", (req, res) => {
  const { dept, name, items, other, notes, link, urgent, delivery } = req.body || {};
  if (!dept || !name || !delivery)
    return res.status(400).json({ ok: false, error: "missing_fields" });

  const supplies = loadDB(SUPPLY_DB);
  const mergedItems = Array.isArray(items) ? items.slice(0) : [];
  if (other && String(other).trim()) mergedItems.push("Other: " + String(other).trim());
  const item = {
    id: "sup-" + Date.now(),
    name: String(name).trim(),
    dept: String(dept).trim(),
    items: mergedItems,
    notes: notes ? String(notes).trim() : "",
    link: link ? String(link).trim() : "",
    urgent: urgent ? String(urgent) : "No",
    delivery: String(delivery),
    completed: false,
    submittedAt: new Date().toISOString()
  };
  supplies.push(item);
  saveDB(SUPPLY_DB, supplies);
  res.json({ ok: true, id: item.id });
});

// --- ADMIN APIs (read + mark complete only) ---
r.get("/api/admin/invoices", requireAdmin, (req, res) => {
  res.json(loadDB(INVOICE_DB));
});
r.get("/api/admin/supplies", requireAdmin, (req, res) => {
  res.json(loadDB(SUPPLY_DB));
});
r.post("/api/admin/invoices/:id/complete", requireAdmin, (req, res) => {
  const invoices = loadDB(INVOICE_DB);
  const it = invoices.find((x) => x.id === req.params.id);
  if (!it) return res.status(404).json({ error: "not_found" });
  it.completed = true;
  saveDB(INVOICE_DB, invoices);
  res.json({ ok: true });
});
r.post("/api/admin/supplies/:id/complete", requireAdmin, (req, res) => {
  const supplies = loadDB(SUPPLY_DB);
  const it = supplies.find((x) => x.id === req.params.id);
  if (!it) return res.status(404).json({ error: "not_found" });
  it.completed = true;
  saveDB(SUPPLY_DB, supplies);
  res.json({ ok: true });
});

// -------- MOUNT ROUTER BEFORE STATIC --------
app.use(BASE_PATH, r);

// -------- CONFIG.JS (client discovers base path) --------
app.get(`${BASE_PATH}/config.js`, (req, res) => {
  res.type("application/javascript").send(`window.__BASE_PATH__ = "${BASE_PATH}";`);
});

// -------- PAGE GUARD MIDDLEWARE (hard server-side protection) --------
const PROTECTED = new Set([
  "/", "/index.html", "/invoice.html", "/supply.html", "/admin.html"
]);
app.use(BASE_PATH, (req, res, next) => {
  const p = req.path;

  // Allow public assets
  const PUBLIC_OK = ["/login.html", "/config.js", "/auth.js", "/favicon.ico"];
  if (PUBLIC_OK.includes(p)) return next();

  // Protect main pages
  if (PROTECTED.has(p)) {
    if (!req.session.user) {
      return res.redirect(`${BASE_PATH}/login.html`);
    }
    if (p === "/admin.html" && req.session.user.role !== "admin") {
      return res.redirect(`${BASE_PATH}/index.html`);
    }
  }
  next();
});

// -------- STATIC (must come after guards) --------
const publicDir = path.join(__dirname, "public");
app.use(BASE_PATH, express.static(publicDir));

// Root route: if unauth → login; else → index or admin based on role
app.get(BASE_PATH === "/" ? "/" : `${BASE_PATH}/`, (req, res) => {
  if (!req.session?.user) return res.redirect(`${BASE_PATH}/login.html`);
  const dest = req.session.user.role === "admin" ? "admin.html" : "index.html";
  res.redirect(`${BASE_PATH}/${dest}`);
});

// -------- START --------
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}${BASE_PATH}`);
});