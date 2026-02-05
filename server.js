require("dotenv").config();
const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const Database = require("better-sqlite3");
const argon2 = require("argon2");
const crypto = require("crypto");
const { createUser } = require("./user_service");
const { encryptGCM, decryptGCM } = require("./crypto_helpers");

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true }
}));

// prevent unauthenticated users from directly loading app.html
app.get("/app.html", (req, res, next) => {
  if (!req.session.userId) {
    return res.redirect("/login.html");
  }
  next();
});

app.use(express.static("public"));

const db = new Database("app.db");

// --- init tables
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  enc_user_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS secrets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  label TEXT NOT NULL,
  enc_data TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

const MASTER_KEY = Buffer.from(process.env.MASTER_KEY_BASE64, "base64");
if (MASTER_KEY.length !== 32) throw new Error("MASTER_KEY must be 32 bytes base64");

// --- helpers
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "not authenticated" });
  next();
}

function getUserByUsername(username) {
  return db.prepare("SELECT * FROM users WHERE username = ?").get(username);
}

function getUserKeyForSession(userRow) {
  // decrypt per-user key using MASTER_KEY
  const userKey = decryptGCM(userRow.enc_user_key, MASTER_KEY);
  if (userKey.length !== 32) throw new Error("invalid user key length");
  return userKey;
}


app.get("/", (req, res) => {
  res.redirect("/login.html");
});

// --- routes
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = getUserByUsername(username);
  if (!user) return res.status(401).json({ error: "invalid credentials" });

  const ok = await argon2.verify(user.password_hash, password);
  if (!ok) return res.status(401).json({ error: "invalid credentials" });

  req.session.userId = user.id;
  res.json({ ok: true });
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.post("/secret", requireAuth, (req, res) => {
  const { label, data } = req.body;
  if (!label || typeof data !== "string") return res.status(400).json({ error: "bad input" });

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId);
  const userKey = getUserKeyForSession(user);

  const enc_data = encryptGCM(Buffer.from(data, "utf8"), userKey);

  const info = db.prepare(
    "INSERT INTO secrets (user_id, label, enc_data) VALUES (?, ?, ?)"
  ).run(user.id, label, enc_data);

  res.json({ ok: true, secretId: info.lastInsertRowid });
});

app.get("/secret/:id", requireAuth, (req, res) => {
  const secretId = Number(req.params.id);

  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId);
  const row = db.prepare(
    "SELECT * FROM secrets WHERE id = ? AND user_id = ?"
  ).get(secretId, user.id);

  if (!row) return res.status(404).json({ error: "not found" });

  const userKey = getUserKeyForSession(user);
  const plaintext = decryptGCM(row.enc_data, userKey).toString("utf8");

  res.json({ ok: true, label: row.label, data: plaintext, created_at: row.created_at });
});

app.get("/secret-raw/:id", requireAuth, (req, res) => {
  const secretId = Number(req.params.id);

  const row = db.prepare(
    "SELECT id, user_id, label, enc_data, created_at FROM secrets WHERE id = ? AND user_id = ?"
  ).get(secretId, req.session.userId);

  if (!row) return res.status(404).json({ error: "not found" });

  res.json({ ok: true, ...row });
});

app.get("/my-secrets", requireAuth, (req, res) => {
  const rows = db.prepare(
    "SELECT id, label, created_at FROM secrets WHERE user_id = ? ORDER BY id DESC"
  ).all(req.session.userId);

  res.json({ ok: true, items: rows });
});

app.listen(3000, () => console.log("http://localhost:3000"));
