/**
 * db.js — Schema and data access.
 *
 * THE ANONYMITY GUARANTEE LIVES IN THIS SCHEMA:
 *
 *   - `ballots` has NO member_id, NO credential_id, NO timestamp, and is a
 *     WITHOUT ROWID table keyed by a random UUID, so even physical storage
 *     order reveals nothing about when a ballot arrived (OLMS: "randomizing
 *     the order in which votes are stored so that the ballot tally reveals
 *     no information about the order in which votes were cast").
 *
 *   - `credentials` records that a credential was redeemed (for one-person-
 *     one-vote and observable turnout) but holds no ballot reference.
 *
 *   - There is no foreign key, join path, or log entry connecting the two.
 */
'use strict';

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const { chainHash } = require('./crypto');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'ballot.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','observer')),
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS members (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT,
  member_number TEXT,
  good_standing INTEGER NOT NULL DEFAULT 1,
  needs_paper_ballot INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS elections (
  id INTEGER PRIMARY KEY,
  title TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('officer_election','delegate_election','dues_assessment','contract_ratification','bylaw_amendment','budget','other')),
  iaff_legal_approval TEXT,   -- for secret-ballot kinds: recorded acknowledgment/reference of IAFF Legal Dept approval (per IAFF Best Practices & Model Rules)
  is_test INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','credentials_issued','open','closed','tallied')),
  notice_sent_on TEXT,
  opens_at TEXT,
  closes_at TEXT,
  public_key TEXT,
  key_shares_total INTEGER,
  key_threshold INTEGER,
  keyholders TEXT,            -- JSON array of keyholder names/roles (for the record; never the shares)
  eligibility_snapshot TEXT,  -- JSON of eligible member ids at credential issuance
  results_json TEXT,
  tallied_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS races (
  id INTEGER PRIMARY KEY,
  election_id INTEGER NOT NULL REFERENCES elections(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  seats INTEGER NOT NULL DEFAULT 1,
  threshold TEXT NOT NULL DEFAULT 'majority' CHECK (threshold IN ('majority','two_thirds','plurality')),
  position INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS candidates (
  id INTEGER PRIMARY KEY,
  race_id INTEGER NOT NULL REFERENCES races(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  position INTEGER NOT NULL DEFAULT 0
);

/*
 * Credentials: one row per issued credential.
 *  - code_hash/salt: scrypt of the credential; plaintext is never stored.
 *  - member_ref: AES-256-GCM-encrypted member id, decryptable only with the
 *    REISSUE_KEY (held outside the DB), used solely to void-and-reissue a
 *    lost credential. It cannot connect to any ballot.
 *  - redeemed_on: DATE ONLY (no time). Combined with the ballots table having
 *    no ordering information, redemption records cannot be correlated to
 *    individual ballots.
 */
CREATE TABLE IF NOT EXISTS credentials (
  id INTEGER PRIMARY KEY,
  election_id INTEGER NOT NULL REFERENCES elections(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  member_ref TEXT NOT NULL,
  voided INTEGER NOT NULL DEFAULT 0,
  redeemed INTEGER NOT NULL DEFAULT 0,
  redeemed_on TEXT
);
CREATE INDEX IF NOT EXISTS idx_credentials_election ON credentials(election_id);

/*
 * Turnout list (who has voted — a right of observers under 29 CFR 452), kept
 * SEPARATE from ballots. Date only, alphabetical presentation.
 */
CREATE TABLE IF NOT EXISTS turnout (
  election_id INTEGER NOT NULL REFERENCES elections(id) ON DELETE CASCADE,
  member_id INTEGER NOT NULL REFERENCES members(id),
  voted_on TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT 'electronic',
  PRIMARY KEY (election_id, member_id)
);

/*
 * BALLOTS — deliberately information-poor. Random UUID key, WITHOUT ROWID,
 * encrypted payload only. Nothing else. Ever.
 */
CREATE TABLE IF NOT EXISTS ballots (
  id TEXT PRIMARY KEY,
  election_id INTEGER NOT NULL,
  payload TEXT NOT NULL
) WITHOUT ROWID;

/*
 * Tamper-evident audit log: each row commits to the previous row's hash.
 */
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY,
  at TEXT NOT NULL DEFAULT (datetime('now')),
  actor TEXT NOT NULL,
  event TEXT NOT NULL,
  detail TEXT,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL
);
`);

/* ---------------- audit log ---------------- */

const GENESIS = '0'.repeat(64);

const getLastHash = db.prepare('SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1');
const insertLog = db.prepare(
  'INSERT INTO audit_log (actor, event, detail, prev_hash, entry_hash) VALUES (?,?,?,?,?)'
);

/**
 * Append a tamper-evident log entry. NOTE: never pass voter-identifying
 * detail together with ballot events — ballot casting is logged only as
 * an anonymous counter event.
 */
function audit(actor, event, detail) {
  const prev = getLastHash.get();
  const prevHash = prev ? prev.entry_hash : GENESIS;
  const entryJson = JSON.stringify({ actor, event, detail: detail || null });
  const entryHash = chainHash(prevHash, entryJson);
  insertLog.run(actor, event, detail || null, prevHash, entryHash);
}

/** Verify the whole chain; returns { ok, brokenAt } */
function verifyAuditChain() {
  const rows = db.prepare('SELECT * FROM audit_log ORDER BY id ASC').all();
  let prevHash = GENESIS;
  for (const r of rows) {
    const entryJson = JSON.stringify({ actor: r.actor, event: r.event, detail: r.detail });
    const expect = chainHash(prevHash, entryJson);
    if (r.prev_hash !== prevHash || r.entry_hash !== expect) {
      return { ok: false, brokenAt: r.id, total: rows.length };
    }
    prevHash = r.entry_hash;
  }
  return { ok: true, brokenAt: null, total: rows.length, tip: prevHash };
}

module.exports = { db, audit, verifyAuditChain };
