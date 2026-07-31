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
 *
 *   - The journal settings below matter as much as the schema: see the
 *     comment on journal_mode. A ballot insert and a turnout insert share
 *     one transaction (that is what makes double-voting impossible), so the
 *     database must not leave behind any file recording which writes were
 *     committed together.
 */
'use strict';

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const { chainHash, randomHex } = require('./crypto');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'ballot.db'));

/*
 * BALLOT-SECRECY PRAGMAS — do not change these without reading this comment.
 *
 * journal_mode = DELETE (NOT WAL):
 *   Casting a ballot writes the turnout row (which identifies the member) and
 *   the sealed ballot row inside a single transaction. That single transaction
 *   is required for one-person-one-vote: it is what makes a double-spend race
 *   impossible. But WAL mode keeps a persistent `ballot.db-wal` file that
 *   records which writes were committed together, which would pair each
 *   member with the ballot committed alongside their turnout row — the exact
 *   voter-to-vote link this system exists to prevent. In DELETE mode the
 *   rollback journal is removed as soon as each transaction commits, so no
 *   such artifact survives. The cost is reduced read/write concurrency, which
 *   is irrelevant at union-local scale on a single instance.
 *
 * secure_delete = ON:
 *   Overwrites deleted content instead of leaving it in freed pages. Required
 *   because the database file is retained for one year as the election record,
 *   and because the member<->credential map is purged after voting closes.
 *
 * synchronous = FULL:
 *   The database IS the election record. Durability over speed.
 */
db.pragma('journal_mode = DELETE');
db.pragma('secure_delete = ON');
db.pragma('synchronous = FULL');
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
 *  - code_hash/salt: salted SHA-256 of the credential; plaintext is never
 *    stored. A fast hash (rather than a slow KDF like scrypt/bcrypt) is
 *    appropriate because credentials are uniformly random ~80-bit secrets,
 *    so brute-forcing the space is infeasible regardless of hash speed.
 *  - member_ref: AES-256-GCM-encrypted member id, decryptable only with the
 *    REISSUE_KEY (held outside the DB), used solely to void-and-reissue a
 *    lost credential. It cannot connect to any ballot. Set to '' by
 *    purgeReissueMap() once voting closes and reissue is no longer possible.
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

/* ---------------- reissue-key custody ---------------- */

/*
 * The reissue key decrypts the member<->credential map (never any ballot).
 * In production it MUST be supplied out-of-band via the REISSUE_KEY env var:
 * we refuse to auto-generate and store it in this database, because doing so
 * would place the key inside the very election record it is meant to protect.
 * Outside production (tests, local demos) we auto-generate and persist it for
 * convenience.
 *
 * Second guard: NODE_ENV is easy to forget on a hosting provider. So we also
 * refuse to auto-generate once any non-test election exists in this database,
 * regardless of NODE_ENV. A real election never gets the convenience path.
 */
function realElectionExists() {
  return !!db.prepare('SELECT id FROM elections WHERE is_test = 0 LIMIT 1').get();
}

function getReissueKey() {
  if (process.env.REISSUE_KEY) return process.env.REISSUE_KEY;

  if (process.env.NODE_ENV === 'production' || realElectionExists()) {
    throw Object.assign(
      new Error('REISSUE_KEY is not set. For any non-test election it must be provided as a 64-hex-char environment variable and kept outside the database; refusing to auto-generate it.'),
      { publicMessage: 'Server is misconfigured: the reissue key is missing. Contact the administrator.' }
    );
  }

  let r = db.prepare("SELECT value FROM settings WHERE key='reissue_key'").get();
  if (!r) {
    db.prepare("INSERT INTO settings (key,value) VALUES ('reissue_key', ?)").run(randomHex(32));
    r = db.prepare("SELECT value FROM settings WHERE key='reissue_key'").get();
  }
  return r.value;
}

/* ---------------- reissue-map purge ---------------- */

/**
 * Destroy the member<->credential map for one election once voting has closed.
 *
 * Reissuing a lost credential is only possible while voting is open, so after
 * close the map has no remaining purpose — and keeping it is the one stored
 * artifact that a stolen database plus a stolen REISSUE_KEY could exploit.
 * Removing it before the tally ceremony eliminates that class of exposure
 * entirely, and it is a strong, verifiable statement in a compliance packet.
 *
 * The hashed credentials, turnout list, sealed ballots, and audit log all
 * remain intact for the one-year retention requirement. Only the encrypted
 * name-to-credential pointer is destroyed.
 *
 * Refuses to run while voting is still open. Must be called from an
 * authenticated admin route and recorded in the audit log by the caller.
 */
function purgeReissueMap(electionId) {
  const e = db.prepare('SELECT id, status FROM elections WHERE id=?').get(electionId);
  if (!e) throw new Error('No such election.');
  if (e.status !== 'closed' && e.status !== 'tallied') {
    throw Object.assign(
      new Error('Refusing to purge the reissue map before voting is closed.'),
      { publicMessage: 'Close voting first. While voting is open, the map is still needed to reissue a lost credential.' }
    );
  }
  const info = db.prepare("UPDATE credentials SET member_ref='' WHERE election_id=? AND member_ref<>''").run(electionId);
  /* VACUUM cannot run inside a transaction. With secure_delete = ON it
   * rewrites the file so the purged values do not survive in freed pages. */
  db.exec('VACUUM');
  return info.changes;
}

module.exports = { db, audit, verifyAuditChain, getReissueKey, purgeReissueMap };
