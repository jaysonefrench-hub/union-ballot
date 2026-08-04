/**
 * scripts/decrypt-backup.js — restore a Teller encrypted backup (.tellerbk).
 *
 * Usage:
 *   BACKUP_KEY=<64 hex chars> node scripts/decrypt-backup.js <input.tellerbk> <output.db>
 *
 * Produces a plain SQLite database file you can open with any SQLite tool.
 * Uses only Node's built-in crypto — no dependencies, so it runs anywhere.
 * The backup format is:  "TELLERBK1\n" | iv(12) | gcmTag(16) | ciphertext
 * (AES-256-GCM). See src/routes/backup.js for how backups are created.
 */
'use strict';

const fs = require('fs');
const crypto = require('crypto');

const MAGIC = Buffer.from('TELLERBK1\n', 'utf8');
const [, , inFile, outFile] = process.argv;

if (!inFile || !outFile) {
  console.error('Usage: BACKUP_KEY=<64 hex chars> node scripts/decrypt-backup.js <input.tellerbk> <output.db>');
  process.exit(2);
}
const keyHex = (process.env.BACKUP_KEY || '').trim();
if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
  console.error('Set BACKUP_KEY to the 64-hexadecimal-character key that was used to create this backup.');
  process.exit(2);
}

const buf = fs.readFileSync(inFile);
if (buf.length < MAGIC.length + 12 + 16 || !buf.subarray(0, MAGIC.length).equals(MAGIC)) {
  console.error('That does not look like a Teller backup file (bad header).');
  process.exit(1);
}

let off = MAGIC.length;
const iv = buf.subarray(off, off + 12); off += 12;
const tag = buf.subarray(off, off + 16); off += 16;
const ct = buf.subarray(off);

const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), iv);
decipher.setAuthTag(tag);
let plain;
try {
  plain = Buffer.concat([decipher.update(ct), decipher.final()]);
} catch (e) {
  console.error('Decryption failed — wrong BACKUP_KEY, or the file is corrupt or was tampered with.');
  process.exit(1);
}
fs.writeFileSync(outFile, plain);
console.log(`Wrote ${plain.length} bytes to ${outFile}. Open it with any SQLite tool.`);
