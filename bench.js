require("dotenv").config();
const Database = require("better-sqlite3");
const argon2 = require("argon2");
const crypto = require("crypto");
const { encryptGCM, decryptGCM } = require("./crypto_helpers");

const db = new Database("app.db");

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

function nowNs() { return process.hrtime.bigint(); }
function ms(startNs, endNs) { return Number(endNs - startNs) / 1e6; }

function getUser(username) {
  return db.prepare("SELECT * FROM users WHERE username = ?").get(username);
}

function getUserKey(userRow) {
  return decryptGCM(userRow.enc_user_key, MASTER_KEY);
}

function makePayload(sizeBytes) {
  // deterministic-ish data to avoid compressibility tricks
  return crypto.randomBytes(sizeBytes);
}

function mean(arr) { return arr.reduce((a,b)=>a+b,0) / arr.length; }

async function benchAuth(username, password, rounds = 10) {
  const user = getUser(username);
  if (!user) throw new Error("User not found. Seed first.");

  const times = [];
  for (let i = 0; i < rounds; i++) {
    const t0 = nowNs();
    const ok = await argon2.verify(user.password_hash, password);
    const t1 = nowNs();
    if (!ok) throw new Error("Password invalid (bench)");
    times.push(ms(t0, t1));
  }
  return { avgMs: mean(times), minMs: Math.min(...times), maxMs: Math.max(...times) };
}

function benchEncDec(username, sizes, roundsPerSize = 5) {
  const user = getUser(username);
  if (!user) throw new Error("User not found. Seed first.");
  const userKey = getUserKey(user);

  const insertStmt = db.prepare("INSERT INTO secrets (user_id, label, enc_data) VALUES (?, ?, ?)");
  const selectStmt = db.prepare("SELECT enc_data FROM secrets WHERE id = ? AND user_id = ?");

  const results = [];

  for (const size of sizes) {
    const encTimes = [];
    const insTimes = [];
    const selTimes = [];
    const decTimes = [];
    let plaintextLen = size;
    let ciphertextLen = 0;

    for (let r = 0; r < roundsPerSize; r++) {
      const payload = makePayload(size);

      // encrypt
      let t0 = nowNs();
      const enc = encryptGCM(payload, userKey);
      let t1 = nowNs();
      encTimes.push(ms(t0, t1));
      ciphertextLen = Buffer.byteLength(enc, "utf8");

      // insert
      t0 = nowNs();
      const info = insertStmt.run(user.id, `bench_${size}`, enc);
      t1 = nowNs();
      insTimes.push(ms(t0, t1));

      // select
      t0 = nowNs();
      const row = selectStmt.get(info.lastInsertRowid, user.id);
      t1 = nowNs();
      selTimes.push(ms(t0, t1));

      // decrypt
      t0 = nowNs();
      const dec = decryptGCM(row.enc_data, userKey);
      t1 = nowNs();
      decTimes.push(ms(t0, t1));

      if (!dec.equals(payload)) throw new Error(`Mismatch at size ${size}`);
    }

    results.push({
      sizeBytes: plaintextLen,
      ciphertextBytes: ciphertextLen,
      encAvgMs: mean(encTimes),
      insertAvgMs: mean(insTimes),
      selectAvgMs: mean(selTimes),
      decAvgMs: mean(decTimes),
    });
  }

  return results;
}

(async () => {
  const username = "alice";
  const password = "alice_password123";

  const auth = await benchAuth(username, password, 10);
  console.log("Auth (argon2.verify) ms:", auth);

  const sizes = [1024, 10*1024, 100*1024, 1024*1024, 5*1024*1024];
  const results = benchEncDec(username, sizes, 5);

  console.table(results);
  db.close();
})();
