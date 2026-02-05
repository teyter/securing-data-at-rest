const { createUser } = require("./user_service");

async function seedIfNeeded(db, masterKey) {
  const count = db.prepare("SELECT COUNT(*) AS c FROM users").get().c;

  if (count > 0) {
    console.log("Users already exist, skipping seed");
    return;
  }

  console.log("Seeding initial users...");

  await createUser(db, masterKey, "alice", "alice_password123");
  await createUser(db, masterKey, "bob", "bob_password123");

  console.log("Seed complete");
}

module.exports = { seedIfNeeded };
