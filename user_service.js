const crypto = require("crypto");
const argon2 = require("argon2");
const { encryptGCM } = require("./crypto_helpers");

async function createUser(db, masterKey, username, password) {
  const password_hash = await argon2.hash(password, {
    type: argon2.argon2id
  });

  const userKey = crypto.randomBytes(32);
  const enc_user_key = encryptGCM(userKey, masterKey);

  const stmt = db.prepare(`
    INSERT INTO users (username, password_hash, enc_user_key)
    VALUES (?, ?, ?)
  `);

  return stmt.run(username, password_hash, enc_user_key);
}

module.exports = { createUser };
