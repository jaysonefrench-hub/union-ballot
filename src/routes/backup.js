/**
 * routes/backup.js — Encrypted snapshot of the whole database (helper).
 *
 * MULTI-LOCAL NOTE: the database now holds EVERY local's data, so the
 * whole-database backup is a PLATFORM-ADMINISTRATOR function (mounted by
 * src/routes/platform.js), not a committee one — a committee download of the
 * full database would hand one local every other local's roster. Committees
 * keep their own per-election records archive (their one-year retention
 * duty) from the election page.
 *
 * WHY ENCRYPTED: a backup of the election database contains member names and
 * emails, turnout, hashed credentials, the (already-encrypted) reissue map,
 * results, and the audit log. It is retained for a year and may be copied
 * off-site, so it must never sit around as a readable file. Each backup is
 * sealed with AES-256-GCM under BACKUP_KEY: a 256-bit hex key supplied as an
 * environment variable, kept OUTSIDE the database and separate from
 * REISSUE_KEY and SESSION_SECRET.
 *
 * WHY IT CANNOT CONTAIN KEY SHARES: the election private key is split into
 * Shamir shares that are shown once at the key ceremony and NEVER written to
 * the database (the elections table records only the public key and the
 * keyholders' names). The private key is never stored either. A database
 * backup therefore cannot contain any share or plaintext election key — only
 * material that is already encrypted or non-secret. No backup can open a
 * ballot.
 *
 * Restore with scripts/decrypt-backup.js.
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { db } = require('../db');

const MAGIC = Buffer.from('UNIONBALLOT1\n', 'utf8'); // file-format marker + version

function backupKey() {
  const k = (process.env.BACKUP_KEY || '').trim();
  if (!/^[0-9a-fA-F]{64}$/.test(k)) {
    throw Object.assign(
      new Error('BACKUP_KEY must be exactly 64 hexadecimal characters (a 256-bit key).'),
      { publicMessage: 'Encrypted backups are not configured. Set a 64-hex-character BACKUP_KEY environment variable (kept off the server, separate from the reissue key). No backup was created.' }
    );
  }
  return Buffer.from(k, 'hex');
}

/*
 * Consistent snapshot of the live database, sealed as:
 *   MAGIC | iv(12) | tag(16) | ciphertext
 * The snapshot uses SQLite's online-backup API, so it is internally
 * consistent even if taken while the application is running.
 */
async function createEncryptedBackup() {
  const key = backupKey();
  const tmp = path.join(os.tmpdir(), `unionballot-snap-${crypto.randomUUID()}.db`);
  try {
    await db.backup(tmp);
    const plain = fs.readFileSync(tmp);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
    const tag = cipher.getAuthTag();
    plain.fill(0);
    key.fill(0);
    return Buffer.concat([MAGIC, iv, tag, ct]);
  } finally {
    try { fs.unlinkSync(tmp); } catch (_) { /* temp snapshot may already be gone */ }
  }
}

module.exports = { createEncryptedBackup };
