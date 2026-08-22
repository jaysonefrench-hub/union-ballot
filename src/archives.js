/**
 * archives.js — Sealed records archives, written automatically at tally.
 *
 * WHY: the local's committee can already download the records archive by hand,
 * but a local that loses its login, its laptop, or its download can lose the
 * results too. Persisting the archive at the moment of tally means the
 * platform operator can hand a local back its records later, without ever
 * being able to read a ballot: the archive holds the same material as the
 * manual /admin/elections/:id/archive export — election configuration,
 * eligibility snapshot, turnout, HASHED credentials, ENCRYPTED ballots,
 * aggregate results, and the audit log. No key share and no plaintext ballot
 * ever exists in it, so possession of an archive can never open a ballot;
 * that still requires K of N keyholders acting together.
 *
 * ENCRYPTION AT REST: when BACKUP_KEY is configured (the same 64-hex-char key
 * that seals database backups), each archive file is sealed with AES-256-GCM
 * in the exact backup file format ("UNIONBALLOT1\n" | iv | tag | ciphertext),
 * so scripts/decrypt-backup.js opens both. Without BACKUP_KEY the archive is
 * written as plain JSON — identical content to the export the committee can
 * already download unencrypted — and the audit log records which happened.
 *
 * MULTI-LOCAL NOTE: this instance serves ONE local today. The archives table
 * and the platform stats page are deliberately shaped (per-election metadata,
 * counts only) so future multi-local deployments can roll up into the same
 * reporting without changing what is collected.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { db, verifyAuditChain, DATA_DIR } = require('./db');

const ARCHIVE_DIR = path.join(DATA_DIR, 'archives');

/* Same file-format marker as encrypted database backups (src/routes/backup.js):
 * MAGIC | iv(12) | tag(16) | ciphertext, AES-256-GCM under BACKUP_KEY.
 * Reusing the format means one recovery tool (scripts/decrypt-backup.js)
 * opens both backups and archives. */
const MAGIC = Buffer.from('UNIONBALLOT1\n', 'utf8');

/** BACKUP_KEY if present and well-formed, else null (archive falls back to
 * plaintext JSON rather than failing the tally). */
function archiveKey() {
  const k = (process.env.BACKUP_KEY || '').trim();
  return /^[0-9a-fA-F]{64}$/.test(k) ? Buffer.from(k, 'hex') : null;
}

function archiveEncryptionAvailable() {
  return archiveKey() !== null;
}

/**
 * Build the records-archive object for one election. This is the single
 * source of truth for archive contents: the manual admin export and the
 * automatic tally-time archive both call it, so they can never drift apart.
 */
function buildArchive(electionId) {
  const e = db.prepare('SELECT * FROM elections WHERE id=?').get(electionId);
  if (!e) { const err = new Error('no such election'); err.publicMessage = 'Election not found.'; throw err; }
  e.races = db.prepare('SELECT * FROM races WHERE election_id=? ORDER BY position, id').all(e.id);
  for (const r of e.races) r.candidates = db.prepare('SELECT * FROM candidates WHERE race_id=? ORDER BY position, id').all(r.id);
  return {
    generated_at: new Date().toISOString(),
    note: 'LMRDA Section 401(e): preserve this archive and all related records for one year after the election.',
    election: e,
    eligibility_snapshot: JSON.parse(e.eligibility_snapshot || '[]'),
    turnout: db.prepare('SELECT m.name, m.member_number, t.voted_on, t.method FROM turnout t JOIN members m ON m.id=t.member_id WHERE t.election_id=? ORDER BY m.name').all(e.id),
    credentials_hashed: db.prepare('SELECT id, code_hash, salt, voided, redeemed, redeemed_on FROM credentials WHERE election_id=?').all(e.id),
    encrypted_ballots: db.prepare('SELECT id, payload FROM ballots WHERE election_id=? ORDER BY id').all(e.id),
    results: e.results_json ? JSON.parse(e.results_json) : null,
    audit_log: db.prepare('SELECT * FROM audit_log ORDER BY id').all(),
    audit_chain_verification: verifyAuditChain(),
  };
}

/**
 * Persist the sealed records archive for a tallied election under
 * DATA_DIR/archives/ and record its metadata (counts and a file pointer only)
 * in the archives table. Returns the stored row. The caller writes the audit
 * entry — and must treat a failure here as loggable, never as a reason to
 * fail the tally itself.
 */
function writeSealedArchive(electionId) {
  const archive = buildArchive(electionId);
  const e = archive.election;
  const json = Buffer.from(JSON.stringify(archive, null, 2), 'utf8');

  const key = archiveKey();
  let fileBuf; let encrypted;
  if (key) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(json), cipher.final()]);
    const tag = cipher.getAuthTag();
    fileBuf = Buffer.concat([MAGIC, iv, tag, ct]);
    encrypted = 1;
    json.fill(0);
    key.fill(0);
  } else {
    fileBuf = json;
    encrypted = 0;
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, '-').replace('Z', '');
  const filename = `election-${e.id}-records-${stamp}.${encrypted ? 'ubk' : 'json'}`;
  fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
  fs.writeFileSync(path.join(ARCHIVE_DIR, filename), fileBuf);

  const sha256 = crypto.createHash('sha256').update(fileBuf).digest('hex');
  const info = db.prepare(`INSERT INTO archives
    (election_id, election_title, tallied_at, ballot_count, filename, encrypted, sha256, size_bytes)
    VALUES (?,?,?,?,?,?,?,?)`)
    .run(e.id, e.title, e.tallied_at || null, archive.encrypted_ballots.length, filename, encrypted, sha256, fileBuf.length);

  return db.prepare('SELECT * FROM archives WHERE id=?').get(info.lastInsertRowid);
}

/** All stored archives, newest first — metadata only, for the platform page. */
function listArchives() {
  return db.prepare('SELECT * FROM archives ORDER BY id DESC').all();
}

/** Absolute path of one stored archive file (basename-only, so a stored
 * filename can never traverse outside the archive directory). */
function archiveFilePath(filename) {
  return path.join(ARCHIVE_DIR, path.basename(String(filename || '')));
}

module.exports = { buildArchive, writeSealedArchive, listArchives, archiveFilePath, archiveEncryptionAvailable, ARCHIVE_DIR };
