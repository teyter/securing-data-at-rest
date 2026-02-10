require("dotenv").config();
const Database = require("better-sqlite3");
const crypto = require("crypto");
const { createUser } = require("./user_service");

const MASTER_KEY = Buffer.from(process.env.MASTER_KEY_BASE64, "base64");
if (MASTER_KEY.length !== 32) throw new Error("MASTER_KEY must be 32 bytes base64");

const db = new Database("app.db");

// ensure tables exist (safe)
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  enc_user_key TEXT NOT NULL
);
`);

function randPassword(len = 20) {
  // base64 includes +/=. If you prefer alnum only, say so.
  return crypto.randomBytes(len).toString("base64").slice(0, len);
}

async function main() {
  const users = [
    { u: "weak1",   p: "password123" },
    { u: "weak2",   p: "alice_password123" },
    { u: "med1",    p: "CorrectHorseBatteryStaple1" },
    { u: "strong1", p: randPassword(24) },
  ];

  for (const { u, p } of users) {
    try {
      await createUser(db, MASTER_KEY, u, p);
      console.log(`✔ Created ${u}  password="${p}"`);
    } catch {
      console.log(`ℹ ${u} already exists (skipping)`);
    }
  }

  db.close();
}
main().catch(e => { console.error(e); db.close(); process.exit(1); });
