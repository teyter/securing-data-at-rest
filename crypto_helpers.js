const crypto = require("crypto");

function b64(buf) { return Buffer.from(buf).toString("base64"); }
function unb64(s) { return Buffer.from(s, "base64"); }

// bundle format: base64(iv) + "." + base64(ciphertext) + "." + base64(tag)
function encryptGCM(plaintextBuf, keyBuf) {
  const iv = crypto.randomBytes(12); // 96-bit nonce for GCM
  const cipher = crypto.createCipheriv("aes-256-gcm", keyBuf, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${b64(iv)}.${b64(ciphertext)}.${b64(tag)}`;
}

function decryptGCM(bundle, keyBuf) {
  const [ivB64, ctB64, tagB64] = bundle.split(".");
  const iv = unb64(ivB64);
  const ciphertext = unb64(ctB64);
  const tag = unb64(tagB64);

  const decipher = crypto.createDecipheriv("aes-256-gcm", keyBuf, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext;
}

module.exports = { encryptGCM, decryptGCM };
