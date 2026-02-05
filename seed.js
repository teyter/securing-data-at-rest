require("dotenv").config();
const Database = require("better-sqlite3");
const { createUser } = require("./user_service");

const MASTER_KEY = Buffer.from(process.env.MASTER_KEY_BASE64, "base64");
if (MASTER_KEY.length !== 32) {
  throw new Error("MASTER_KEY must be 32 bytes base64");
}

const db = new Database("app.db");

// Ensure tables exist (safe to re-run)
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  enc_user_key TEXT NOT NULL
);
`);

async function seed() {
  try {
    await createUser(db, MASTER_KEY, "alice", "alice_password123");
    console.log("✔ Created user: alice");
  } catch {
    console.log("ℹ User alice already exists");
  }

  try {
    await createUser(db, MASTER_KEY, "bob", "bob_password123");
    console.log("✔ Created user: bob");
  } catch {
    console.log("ℹ User bob already exists");
  }

  db.close();
}

seed().catch(err => {
  console.error("Seeding failed:", err);
  db.close();
});
