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
 *
 * MULTI-LOCAL TENANCY:
 *
 *   One deployment now serves MANY union locals, each a fully walled-off
 *   tenant. `locals` is the tenant table; `members`, `elections`, `users`
 *   (committee/observer accounts), `audit_log`, and `archives` each carry a
 *   `local_id`. Rows that hang off an election — races, candidates,
 *   credentials, ballots, turnout — are scoped TRANSITIVELY: they reference
 *   exactly one election, and every code path reaches them only through an
 *   election row fetched with `WHERE id=? AND local_id=?` (src/tenant.js).
 *   The ballot row itself deliberately stays exactly three fields (random
 *   UUID, election id, ciphertext): adding a local_id there would add no
 *   isolation (the election already pins the local) and would depart from
 *   the documented information-poor shape.
 *
 *   The audit log is hash-chained PER LOCAL: each entry links to the
 *   previous entry of the SAME local, so a local's observers can verify
 *   their complete chain without ever seeing another local's entries.
 *   Entries with local_id NULL form the platform chain (operator-level
 *   events: platform sign-ins, local creation, whole-database backups).
 */
'use strict';

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const { chainHash, randomHex } = require('./crypto');
const { jurisdictionName } = require('./jurisdictions');

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

/*
 * Union locals — the tenant table. Every local is fully isolated from every
 * other: a committee/observer account belongs to exactly one local and is
 * structurally incapable of reaching another local's roster, elections,
 * credentials, ballots, audit log, or archives (enforced at the query layer
 * in src/tenant.js and the route files). Holds ORGANIZATIONAL identity only
 * — never member data.
 */
CREATE TABLE IF NOT EXISTS locals (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  local_number TEXT,          -- e.g. IAFF local number ("947"); optional
  jurisdiction TEXT,          -- two-letter state code of the local
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

/*
 * Platform administrators (super-admins) — the operator role that hosts the
 * instance for many locals. DELIBERATELY a separate table from the per-local
 * \`users\`: no local-scoped account query can ever match a platform account,
 * and no platform account carries a local_id that could be mistaken for
 * committee access. Platform admins see aggregate counts and can create new
 * locals; they can never read a ballot (ballots are sealed to keyholder
 * shares that are never stored) and no platform page exposes member PII.
 */
CREATE TABLE IF NOT EXISTS platform_users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

/*
 * Committee/observer accounts, each belonging to exactly one local. email is
 * the account-recovery address (never a voter's): password-reset links can
 * only be emailed to it. reset_token_hash follows the same discipline as
 * member email-verification tokens — the plaintext token exists only in the
 * reset link, only the SHA-256 hash is stored, it is single-use, and it
 * expires. Usernames stay UNIQUE across the whole instance so sign-in needs
 * no local selector; the account's local_id decides what it can see.
 */
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  local_id INTEGER NOT NULL REFERENCES locals(id),
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','observer')),
  display_name TEXT NOT NULL,
  email TEXT,
  reset_token_hash TEXT,
  reset_token_sent_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

/*
 * Members: one local's roster rows only ever meet that local's elections.
 * email_verified gates ELECTRONIC credential delivery only. A member on the
 * paper-ballot path never needs a verified email. The verification token is
 * stored only as a SHA-256 hash (the plaintext exists only in the
 * verification email / one-time link screen), is single-use, and expires.
 * TEST elections may set demo_skip_email_verify to skip this gate; binding
 * elections never do.
 */
CREATE TABLE IF NOT EXISTS members (
  id INTEGER PRIMARY KEY,
  local_id INTEGER NOT NULL REFERENCES locals(id),
  name TEXT NOT NULL,
  email TEXT,
  member_number TEXT,
  good_standing INTEGER NOT NULL DEFAULT 1,
  needs_paper_ballot INTEGER NOT NULL DEFAULT 0,
  email_verified INTEGER NOT NULL DEFAULT 0,
  email_verified_at TEXT,
  email_verify_token_hash TEXT,
  email_verify_sent_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS elections (
  id INTEGER PRIMARY KEY,
  local_id INTEGER NOT NULL REFERENCES locals(id),
  title TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('officer_election','delegate_election','dues_assessment','contract_ratification','bylaw_amendment','budget','other')),
  jurisdiction TEXT,          -- two-letter state code (e.g. 'FL'); drives jurisdiction-specific legal gates
  perc_variance_ack INTEGER NOT NULL DEFAULT 0, -- committee's recorded claim of a current Florida PERC variance for electronic ratification (never a system approval)
  perc_variance_ref TEXT,     -- optional date/reference for that claimed variance, kept for the record
  iaff_legal_approval TEXT,   -- for secret-ballot kinds: recorded acknowledgment/reference of IAFF Legal Dept approval (per IAFF Best Practices & Model Rules)
  is_test INTEGER NOT NULL DEFAULT 0,
  /*
   * DEMO / TEST dry-run: when is_test=1 AND this flag is 1, electronic
   * credentials may be issued to syntactically valid emails without
   * magic-link verification. Binding elections (is_test=0) must never
   * store or honor a 1 here — application code forces 0 on create/update.
   * Default 0 so a live upgrade of an existing TEST row stays gated until
   * the committee flips the toggle (new TEST creates set 1 in the INSERT).
   */
  demo_skip_email_verify INTEGER NOT NULL DEFAULT 0,
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
 * Credentials: one row per issued credential. Scoped to a local through its
 * election — reachable in code only via an election fetched with a local_id
 * check.
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
 * encrypted payload only. Nothing else. Ever. (No local_id either: the
 * election pins the local; a fourth column would add data, not isolation.)
 */
CREATE TABLE IF NOT EXISTS ballots (
  id TEXT PRIMARY KEY,
  election_id INTEGER NOT NULL,
  payload TEXT NOT NULL
) WITHOUT ROWID;

/*
 * Tamper-evident audit log, hash-chained PER LOCAL: each row commits to the
 * hash of the previous row OF THE SAME local_id, so one local's observers
 * can verify their complete chain in isolation. local_id NULL is the
 * platform chain (operator-level events). Moving an entry between chains
 * breaks the linkage of both chains, so the local_id assignment is itself
 * tamper-evident.
 */
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY,
  local_id INTEGER REFERENCES locals(id),
  at TEXT NOT NULL DEFAULT (datetime('now')),
  actor TEXT NOT NULL,
  event TEXT NOT NULL,
  detail TEXT,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL
);

/*
 * Sealed records archives, written automatically when an election is tallied
 * (same contents as the manual /admin/elections/:id/archive export). The row
 * holds METADATA ONLY — counts and a file pointer, never member data — so the
 * platform-support page can list archives without opening them. election_id
 * and local_id are deliberately NOT foreign keys: an archive is a retention
 * record and must outlive whatever happens to the live election row.
 */
CREATE TABLE IF NOT EXISTS archives (
  id INTEGER PRIMARY KEY,
  local_id INTEGER,
  election_id INTEGER NOT NULL,
  election_title TEXT NOT NULL,
  tallied_at TEXT,
  ballot_count INTEGER NOT NULL DEFAULT 0,
  filename TEXT NOT NULL,
  encrypted INTEGER NOT NULL DEFAULT 0,
  sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

/* ---------------- lightweight migrations ----------------
 * CREATE TABLE IF NOT EXISTS covers fresh databases only. An existing
 * database (a live deployment upgrading in place) needs the new columns
 * added; ALTER TABLE ... ADD COLUMN is idempotent via the presence check.
 * Returns true when the column was ADDED on this boot (i.e. every existing
 * row in that table predates the column). */
function ensureColumn(table, column, ddl) {
  const has = db.prepare(`PRAGMA table_info(${table})`).all().some((c) => c.name === column);
  if (!has) db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
  return !has;
}
ensureColumn('members', 'email_verified', 'email_verified INTEGER NOT NULL DEFAULT 0');
ensureColumn('members', 'email_verified_at', 'email_verified_at TEXT');
ensureColumn('members', 'email_verify_token_hash', 'email_verify_token_hash TEXT');
ensureColumn('members', 'email_verify_sent_at', 'email_verify_sent_at TEXT');
ensureColumn('elections', 'jurisdiction', 'jurisdiction TEXT');
ensureColumn('elections', 'perc_variance_ack', 'perc_variance_ack INTEGER NOT NULL DEFAULT 0');
ensureColumn('elections', 'perc_variance_ref', 'perc_variance_ref TEXT');
ensureColumn('elections', 'demo_skip_email_verify', 'demo_skip_email_verify INTEGER NOT NULL DEFAULT 0');
ensureColumn('users', 'email', 'email TEXT');
ensureColumn('users', 'reset_token_hash', 'reset_token_hash TEXT');
ensureColumn('users', 'reset_token_sent_at', 'reset_token_sent_at TEXT');

/* MULTI-LOCAL upgrade: add local_id to every previously instance-global
 * table. Added NULLABLE on existing databases (SQLite requires a NULL
 * default for a new REFERENCES column); the backfill below assigns every
 * existing row to the default local, after which no NULL remains in any
 * local-owned table and application code always writes an explicit local_id.
 * audit_log.local_id stays legitimately NULL for platform-chain entries. */
ensureColumn('users', 'local_id', 'local_id INTEGER REFERENCES locals(id)');
ensureColumn('members', 'local_id', 'local_id INTEGER REFERENCES locals(id)');
ensureColumn('elections', 'local_id', 'local_id INTEGER REFERENCES locals(id)');
/* For audit_log, a NULL local_id is a LEGITIMATE ongoing state (the platform
 * chain), so its rows count as pre-migration orphans only when the column was
 * added on this very boot — i.e. every row in the table predates tenancy. */
const auditLogPredatesTenancy = ensureColumn('audit_log', 'local_id', 'local_id INTEGER REFERENCES locals(id)');
ensureColumn('archives', 'local_id', 'local_id INTEGER');

/* ---------------- audit log (hash-chained per local) ---------------- */

const GENESIS = '0'.repeat(64);

const getLastHashForLocal = db.prepare(
  'SELECT entry_hash FROM audit_log WHERE local_id IS ? ORDER BY id DESC LIMIT 1'
);
const insertLog = db.prepare(
  'INSERT INTO audit_log (local_id, actor, event, detail, prev_hash, entry_hash) VALUES (?,?,?,?,?,?)'
);

/**
 * Append a tamper-evident log entry to one local's chain, or to the platform
 * chain when localId is null. NOTE: never pass voter-identifying detail
 * together with ballot events — ballot casting is logged only as an
 * anonymous counter event.
 *
 * @param {number|null} localId  the local whose observers may see this entry,
 *                               or null for the operator-level platform chain
 */
function audit(localId, actor, event, detail) {
  /* Guard against a legacy 3-argument call slipping the actor into the
   * localId slot: that would silently mis-file an entry across tenants. */
  if (localId !== null && localId !== undefined && !Number.isInteger(Number(localId))) {
    throw new Error('audit(): localId must be a local id or null (platform chain)');
  }
  if (typeof actor !== 'string' || typeof event !== 'string' || !event) {
    throw new Error('audit(): expected (localId, actor, event, detail)');
  }
  const lid = localId === null || localId === undefined ? null : Number(localId);
  const prev = getLastHashForLocal.get(lid);
  const prevHash = prev ? prev.entry_hash : GENESIS;
  const entryJson = JSON.stringify({ actor, event, detail: detail || null });
  const entryHash = chainHash(prevHash, entryJson);
  insertLog.run(lid, actor, event, detail || null, prevHash, entryHash);
}

/**
 * Verify one local's chain (or the platform chain for localId null);
 * returns { ok, brokenAt }. The entry hash commits to actor/event/detail —
 * the same content format as before multi-tenancy — so chains that predate
 * the migration still verify; the per-local linkage is what makes moving an
 * entry between locals break both chains.
 */
function verifyAuditChain(localId) {
  const lid = localId === null || localId === undefined ? null : Number(localId);
  const rows = db.prepare('SELECT * FROM audit_log WHERE local_id IS ? ORDER BY id ASC').all(lid);
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

/* ---------------- multi-local backfill migration ----------------
 *
 * A database created before multi-tenancy has members/elections/users/audit
 * rows with local_id NULL. They all belonged to the one local the instance
 * served, so they are assigned to ONE default local created here. The
 * default local's audit chain is exactly the old instance-wide chain, in
 * order, so it still verifies. Idempotent: once no NULL rows remain this
 * block does nothing, and the chosen local id is remembered in settings so
 * a partially-applied backfill can never split rows across two locals.
 */

/** Best-effort REAL name for the migrated local, from what the data says:
 *  1. a "Local NNN" pattern in existing election titles (binding first,
 *     newest first — a real local puts its number in its election titles);
 *  2. the instance's own BRAND_LOCAL / BRAND_ORG branding env vars;
 *  3. the most recent (binding-first) election's jurisdiction as a state name;
 *  4. only then a generic fallback. */
function inferDefaultLocalIdentity() {
  const elections = db.prepare(
    'SELECT title, jurisdiction, is_test FROM elections WHERE local_id IS NULL ORDER BY is_test ASC, id DESC'
  ).all();

  let localNumber = null;
  let name = null;

  for (const e of elections) {
    const m = /\blocal\s*#?\s*(\d{1,5})\b/i.exec(String(e.title || ''));
    if (m) { localNumber = m[1]; name = `Local ${m[1]}`; break; }
  }

  const brandLocal = String(process.env.BRAND_LOCAL || '').trim();
  const brandOrg = String(process.env.BRAND_ORG || '').trim();
  if (!name && brandLocal) {
    name = brandOrg && brandOrg !== 'Union Ballot' ? `${brandOrg} ${brandLocal}` : brandLocal;
    const bm = /\blocal\s*#?\s*(\d{1,5})\b/i.exec(brandLocal);
    if (bm) localNumber = bm[1];
  }
  if (!name && brandOrg && brandOrg !== 'Union Ballot') name = brandOrg;

  const jurisdiction = (elections.find((e) => e.jurisdiction) || {}).jurisdiction || null;
  if (!name && jurisdiction && jurisdiction !== 'XX') {
    name = `${jurisdictionName(jurisdiction)} local (migrated)`;
  }
  if (!name) name = 'Migrated local';

  return { name, localNumber, jurisdiction };
}

const migrateToLocals = db.transaction(() => {
  /* members/elections/users/archives can NEVER legitimately hold a NULL
   * local_id, so they are always scanned. audit_log is included only when
   * its local_id column was added on this boot (see above) — afterwards its
   * NULL rows are the live platform chain and must never be swept. */
  const TABLES = ['members', 'elections', 'users', 'archives'];
  if (auditLogPredatesTenancy) TABLES.push('audit_log');
  const orphanCounts = { audit_log: 0 };
  let orphanTotal = 0;
  for (const t of TABLES) {
    orphanCounts[t] = db.prepare(`SELECT COUNT(*) AS n FROM ${t} WHERE local_id IS NULL`).get().n;
    orphanTotal += orphanCounts[t];
  }
  if (orphanTotal === 0) return;

  /* Reuse the remembered default local if a previous run created it. */
  let localId = null;
  const remembered = db.prepare("SELECT value FROM settings WHERE key='default_local_id'").get();
  if (remembered && db.prepare('SELECT id FROM locals WHERE id=?').get(Number(remembered.value))) {
    localId = Number(remembered.value);
  }
  if (!localId) {
    const identity = inferDefaultLocalIdentity();
    const info = db.prepare('INSERT INTO locals (name, local_number, jurisdiction) VALUES (?,?,?)')
      .run(identity.name, identity.localNumber, identity.jurisdiction);
    localId = info.lastInsertRowid;
    db.prepare("INSERT INTO settings (key,value) VALUES ('default_local_id', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
      .run(String(localId));
  }

  for (const t of TABLES) {
    db.prepare(`UPDATE ${t} SET local_id=? WHERE local_id IS NULL`).run(localId);
  }

  /* Audited AFTER the backfill so this entry starts the platform chain
   * (local_id NULL) instead of being swept into the default local. Counts
   * only — never a member name or address. */
  const localName = db.prepare('SELECT name FROM locals WHERE id=?').get(localId).name;
  audit(null, 'system', 'platform.migrated_to_locals',
    `Multi-local migration: existing data assigned to default local #${localId} "${localName}" — `
    + `${orphanCounts.members} roster member(s), ${orphanCounts.elections} election(s), `
    + `${orphanCounts.users} committee/observer account(s), ${orphanCounts.audit_log} audit entrie(s), `
    + `${orphanCounts.archives} archive record(s)`);
  console.log(`[migrate] multi-local backfill: existing rows assigned to default local #${localId} "${localName}"`);
});
migrateToLocals();

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
 * (Deliberately instance-wide, not per-local: one process holds one key.)
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
 * authenticated admin route WITH the caller's local id (tenant check), and
 * recorded in the audit log by the caller.
 */
function purgeReissueMap(electionId, localId) {
  const e = db.prepare('SELECT id, status FROM elections WHERE id=? AND local_id=?').get(electionId, localId);
  if (!e) throw new Error('No such election in this local.');
  if (e.status !== 'closed' && e.status !== 'tallied') {
    throw Object.assign(
      new Error('Refusing to purge the reissue map before voting is closed.'),
      { publicMessage: 'Close voting first. While voting is open, the map is still needed to reissue a lost credential.' }
    );
  }
  const info = db.prepare("UPDATE credentials SET member_ref='' WHERE election_id=? AND member_ref<>''").run(e.id);
  /* VACUUM cannot run inside a transaction. With secure_delete = ON it
   * rewrites the file so the purged values do not survive in freed pages. */
  db.exec('VACUUM');
  return info.changes;
}

module.exports = { db, audit, verifyAuditChain, getReissueKey, purgeReissueMap, DATA_DIR };
