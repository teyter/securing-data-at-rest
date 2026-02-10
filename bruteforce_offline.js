require("dotenv").config();
const Database = require("better-sqlite3");
const argon2 = require("argon2");

const db = new Database("app.db");

function nowNs() { return process.hrtime.bigint(); }
function ms(a, b) { return Number(b - a) / 1e6; }

async function main() {
  const username = "alice";
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user) throw new Error("User not found");

  // small demo wordlist — replace/extend for your report
  const guesses = [
    "password", "123456", "alice", "alice123", "alice_password123",
    "letmein", "qwerty", "admin", "bob_password123"
  ];

  console.log(`Target user: ${username}`);
  console.log(`Guesses: ${guesses.length}`);

  let attempts = 0;
  const t0 = nowNs();

  for (const guess of guesses) {
    attempts++;
    const ok = await argon2.verify(user.password_hash, guess);
    if (ok) {
      const t1 = nowNs();
      console.log(`✅ CRACKED: password="${guess}"`);
      console.log(`Attempts: ${attempts}`);
      console.log(`Time: ${ms(t0, t1).toFixed(2)} ms`);
      db.close();
      return;
    }
  }

  const t1 = nowNs();
  console.log("❌ Not found in wordlist");
  console.log(`Attempts: ${attempts}`);
  console.log(`Time: ${ms(t0, t1).toFixed(2)} ms`);
  db.close();
}

main().catch(e => {
  console.error(e);
  db.close();
  process.exit(1);
});
