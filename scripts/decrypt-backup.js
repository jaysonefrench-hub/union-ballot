/**
 * scripts/decrypt-backup.js — open a Union Ballot encrypted file (.ubk):
 * either a full database backup, or a sealed per-election records archive
 * (written automatically at tally under data/archives/). Both use the same
 * format, so this one tool opens both.
 *
 * Usage:
 *   BACKUP_KEY=<64 hex chars> node scripts/decrypt-backup.js <input.ubk> <output>
 *
 * For a database backup the output is a plain SQLite file (open with any
 * SQLite tool); for a records archive it is the plain JSON archive. Uses only
 * Node's built-in crypto — no dependencies, so it runs anywhere.
 * The file format is:  "UNIONBALLOT1\n" | iv(12) | gcmTag(16) | ciphertext
 * (AES-256-GCM). See src/routes/backup.js and src/archives.js for creation.
 * Note: decrypting an archive never exposes a ballot — the ballots inside it
 * are themselves still sealed to the election key held by the keyholders.
 */
'use strict';

const fs = require('fs');
const crypto = require('crypto');

const MAGIC = Buffer.from('UNIONBALLOT1\n', 'utf8');
const [, , inFile, outFile] = process.argv;

if (!inFile || !outFile) {
  console.error('Usage: BACKUP_KEY=<64 hex chars> node scripts/decrypt-backup.js <input.ubk> <output>');
  console.error('  (works for database backups and for sealed records archives from data/archives/)');
  process.exit(2);
}
const keyHex = (process.env.BACKUP_KEY || '').trim();
if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
  console.error('Set BACKUP_KEY to the 64-hexadecimal-character key that was used to create this backup.');
  process.exit(2);
}

const buf = fs.readFileSync(inFile);
if (buf.length < MAGIC.length + 12 + 16 || !buf.subarray(0, MAGIC.length).equals(MAGIC)) {
  console.error('That does not look like a Union Ballot backup file (bad header).');
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
console.log(`Wrote ${plain.length} bytes to ${outFile} (SQLite database if this was a backup; JSON if it was a records archive).`);
