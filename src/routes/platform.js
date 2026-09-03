/**
 * routes/platform.js — Platform administration: the operator who hosts this
 * instance for MANY union locals (not any local's election committee, and
 * not an observer).
 *
 * WHAT A PLATFORM ADMINISTRATOR CAN DO:
 *   1. SEE AGGREGATE, NO-PII STATS — counts only, broken out per local plus
 *      an all-locals rollup: elections by status, credentials issued,
 *      sealed ballots, turnout rates, roster sizes as numbers. No names, no
 *      emails, no phone numbers, no member lists, no rosters — nothing on
 *      any platform page identifies a person.
 *   2. CREATE A NEW LOCAL and, in the same transaction, provision that
 *      local's very first committee-admin account — the multi-local
 *      replacement for the old one-time /setup flow. The flow only ever
 *      grants access to the local it just created, never an existing one.
 *   3. RECOVERY — download a local's sealed records archive (written
 *      automatically at tally) and generate a one-time password-reset link
 *      for a committee/observer account; and download the encrypted
 *      whole-database backup (which spans every local and therefore cannot
 *      be a committee power).
 *
 * WHAT A PLATFORM ADMINISTRATOR CANNOT DO — the same boundary the old
 * single-local platform-owner key had, extended across many locals:
 *   - read, open, or export any ballot: ballots are sealed to per-election
 *     keys that exist only as the keyholders' shares; archives and backups
 *     contain ciphertext only;
 *   - see any local's member roster or PII: no platform query selects a
 *     member name, email, or phone number;
 *   - manage a local's elections: there is deliberately no platform route
 *     that writes to members, elections, races, candidates, credentials,
 *     ballots, or turnout.
 *
 * AUTHENTICATION: real per-person accounts (platform_users, bcrypt) with
 * their own sign-in — this is an ongoing operational role, not a stats
 * peephole. A committee or observer session grants NOTHING here, and a
 * platform session grants nothing under /admin or /observe.
 *
 * BOOTSTRAP (documented in README.md): the first platform-administrator
 * account is created at /platform/setup —
 *   - if PLATFORM_OWNER_KEY is configured (every existing deployment), the
 *     form requires that key: whoever holds the old key claims the new role.
 *     The key keeps working ONLY as authorization for /platform/setup (also
 *     serving as break-glass recovery if all platform passwords are lost —
 *     rotate the env var and create a fresh account); it no longer opens any
 *     stats page by itself.
 *   - if PLATFORM_OWNER_KEY is not set, open first-run creation is allowed
 *     only while the database is COMPLETELY empty (no locals, accounts,
 *     members, or elections) — the same trust model as the old /setup, where
 *     the person deploying the instance claims it immediately. On a database
 *     with existing data and no key, setup refuses and instructs the
 *     operator to set the env var — so nobody can stumble onto a live
 *     instance and claim the platform role.
 */
'use strict';

const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const { db, audit } = require('../db');
const tenant = require('../tenant');
const { listArchives, archiveFilePath, archiveEncryptionAvailable } = require('../archives');
const { createEncryptedBackup } = require('./backup');
const { beginPasswordReset, RESET_TOKEN_TTL_MINUTES } = require('../reset-tokens');
const { makeRateLimiter } = require('../simple-rate-limit');
const { smtpConfigured } = require('../mailer');
const { checkEmailSyntax } = require('../email-syntax');
const { US_JURISDICTIONS, JURISDICTION_CODES } = require('../jurisdictions');

/* A short key is not a gate. Below this length the bootstrap key is treated
 * as unset — with a console warning so a truncated paste is diagnosable —
 * rather than pretending a guessable value protects anything. */
const MIN_KEY_LENGTH = 16;
const RAW_KEY = String(process.env.PLATFORM_OWNER_KEY || '').trim();
const PLATFORM_KEY = RAW_KEY.length >= MIN_KEY_LENGTH ? RAW_KEY : null;
if (RAW_KEY && !PLATFORM_KEY) {
  console.error(`PLATFORM_OWNER_KEY is set but shorter than ${MIN_KEY_LENGTH} characters, so it cannot authorize platform setup. Use a long random secret, e.g. \`openssl rand -hex 32\`.`);
}

/** Constant-time comparison; hashing first makes unequal lengths safe. */
function keyMatches(supplied) {
  if (!PLATFORM_KEY) return false;
  const a = crypto.createHash('sha256').update(String(supplied || '')).digest();
  const b = crypto.createHash('sha256').update(PLATFORM_KEY).digest();
  return crypto.timingSafeEqual(a, b);
}

/* ------------------------- aggregate stats ------------------------- */
/* Counts only. No query in this section may select a name, an email, a
 * phone number, or any other per-person field. Every query takes @lid:
 * a local id for that local's numbers, or NULL for the all-locals rollup —
 * the same code path computes both, so the rollup can never accidentally
 * carry more detail than the per-local view. */

function turnoutSummary(rows) {
  /* rows: elections with a non-empty eligibility snapshot. Overall rate =
   * all voters over all eligible; average rate = mean of per-election rates
   * (small elections weigh equally). Both are useful to a sponsor. */
  let eligible = 0; let voted = 0; const rates = [];
  for (const r of rows) {
    const el = JSON.parse(r.eligibility_snapshot || '[]').length;
    if (el === 0) continue;
    const v = db.prepare('SELECT COUNT(*) AS n FROM turnout WHERE election_id=?').get(r.id).n;
    eligible += el; voted += v; rates.push(v / el);
  }
  return {
    elections: rates.length,
    eligible,
    voted,
    overall_pct: eligible > 0 ? Math.round((voted / eligible) * 1000) / 10 : null,
    average_pct: rates.length > 0 ? Math.round((rates.reduce((a, b) => a + b, 0) / rates.length) * 1000) / 10 : null,
  };
}

function computeStats(localId) {
  const p = { lid: localId === null || localId === undefined ? null : Number(localId) };

  const byStatus = { draft: 0, credentials_issued: 0, open: 0, closed: 0, tallied: 0 };
  for (const r of db.prepare('SELECT status, COUNT(*) AS n FROM elections WHERE (@lid IS NULL OR local_id=@lid) GROUP BY status').all(p)) byStatus[r.status] = r.n;
  const totalElections = Object.values(byStatus).reduce((a, b) => a + b, 0);
  const testElections = db.prepare('SELECT COUNT(*) AS n FROM elections WHERE is_test=1 AND (@lid IS NULL OR local_id=@lid)').get(p).n;

  /* Ballots three ways: sealed rows stored (electronic), ballots counted in
   * tallied results (sum of results_json.ballots_cast), and paper ballots
   * recorded as received. */
  const sealedBallots = db.prepare('SELECT COUNT(*) AS n FROM ballots b JOIN elections e ON e.id=b.election_id WHERE (@lid IS NULL OR e.local_id=@lid)').get(p).n;
  const sealedBallotsTest = db.prepare('SELECT COUNT(*) AS n FROM ballots b JOIN elections e ON e.id=b.election_id WHERE e.is_test=1 AND (@lid IS NULL OR e.local_id=@lid)').get(p).n;
  let talliedBallots = 0;
  for (const r of db.prepare("SELECT results_json FROM elections WHERE status='tallied' AND results_json IS NOT NULL AND (@lid IS NULL OR local_id=@lid)").all(p)) {
    try { talliedBallots += Number(JSON.parse(r.results_json).ballots_cast) || 0; } catch (_) { /* a malformed row must not break the stats page */ }
  }
  const paperBallots = db.prepare("SELECT COUNT(*) AS n FROM turnout t JOIN elections e ON e.id=t.election_id WHERE t.method='paper' AND (@lid IS NULL OR e.local_id=@lid)").get(p).n;

  const creds = db.prepare('SELECT COUNT(*) AS total, COALESCE(SUM(c.redeemed),0) AS redeemed, COALESCE(SUM(c.voided),0) AS voided FROM credentials c JOIN elections e ON e.id=c.election_id WHERE (@lid IS NULL OR e.local_id=@lid)').get(p);

  const snapshotRows = db.prepare('SELECT id, is_test, eligibility_snapshot FROM elections WHERE eligibility_snapshot IS NOT NULL AND (@lid IS NULL OR local_id=@lid)').all(p);
  return {
    elections: {
      total: totalElections,
      by_status: byStatus,
      completed: byStatus.tallied,
      in_preparation: byStatus.draft + byStatus.credentials_issued,
      test: testElections,
      binding: totalElections - testElections,
    },
    credentials: {
      issued: creds.total,
      redeemed: creds.redeemed,
      voided: creds.voided,
    },
    ballots: {
      sealed_stored: sealedBallots,
      sealed_binding: sealedBallots - sealedBallotsTest,
      sealed_test: sealedBallotsTest,
      counted_in_tallies: talliedBallots,
      paper_recorded: paperBallots,
    },
    turnout: {
      all: turnoutSummary(snapshotRows),
      binding: turnoutSummary(snapshotRows.filter((r) => !r.is_test)),
      test: turnoutSummary(snapshotRows.filter((r) => r.is_test)),
    },
    roster_size: db.prepare('SELECT COUNT(*) AS n FROM members WHERE (@lid IS NULL OR local_id=@lid)').get(p).n,
  };
}

module.exports = function platformRoutes({ flash }) {
  const router = express.Router();
  const authLimiter = makeRateLimiter({ windowMs: 15 * 60 * 1000, max: 20 });

  function notFound(res) {
    return res.status(404).render('error', { title: 'Not found', message: 'That page does not exist.' });
  }

  /** The signed-in platform administrator, re-read from the database on
   * every request (a deleted account takes effect immediately). Committee
   * and observer sessions are deliberately irrelevant here. */
  function currentPlatformAdmin(req) {
    const sess = req.session && req.session.platform_admin;
    if (!sess) return null;
    return db.prepare('SELECT * FROM platform_users WHERE id=?').get(sess.id) || null;
  }

  function requirePlatformAdmin(req, res, next) {
    const admin = currentPlatformAdmin(req);
    if (!admin) {
      flash(req, 'error', 'Sign in as a platform administrator first.');
      return res.redirect('/platform');
    }
    req.platformAdmin = admin;
    res.locals.platformAdmin = { id: admin.id, username: admin.username, name: admin.display_name };
    next();
  }

  /* ---------------- first-run / recovery bootstrap ---------------- */

  function setupAllowed() {
    if (PLATFORM_KEY) return { ok: true, keyRequired: true };
    if (tenant.instanceIsEmpty()) return { ok: true, keyRequired: false };
    return {
      ok: false,
      keyRequired: false,
      reason: tenant.platformAdminExists()
        ? 'A platform administrator already exists. To add or recover one without a sign-in, set PLATFORM_OWNER_KEY (16+ characters) on the server and return here.'
        : 'This instance already holds election data, so the platform administrator cannot be self-claimed. Set PLATFORM_OWNER_KEY (16+ characters) on the server, restart, and return here to authorize the first platform account.',
    };
  }

  router.get('/setup', (req, res) => {
    const allowed = setupAllowed();
    res.render('platform/setup', {
      title: 'Platform setup',
      allowed,
      adminExists: tenant.platformAdminExists(),
    });
  });

  router.post('/setup', (req, res) => {
    if (authLimiter.blocked(req)) {
      flash(req, 'error', 'Too many attempts from your connection. Wait a few minutes and try again.');
      return res.redirect('/platform/setup');
    }
    const allowed = setupAllowed();
    if (!allowed.ok) {
      flash(req, 'error', allowed.reason);
      return res.redirect('/platform/setup');
    }
    if (allowed.keyRequired && !keyMatches(req.body.key)) {
      /* The submitted value is never recorded anywhere. */
      audit(null, 'system', 'platform.setup_key_rejected', 'Platform setup was attempted with a key that did not match PLATFORM_OWNER_KEY (submitted value not recorded)');
      flash(req, 'error', 'That key was not recognized. Platform setup requires the PLATFORM_OWNER_KEY configured on the server.');
      return res.redirect('/platform/setup');
    }
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    const displayName = String(req.body.display_name || '').trim() || username;
    if (!username || password.length < 10) {
      flash(req, 'error', 'Choose a username and a password of at least 10 characters.');
      return res.redirect('/platform/setup');
    }
    try {
      db.prepare('INSERT INTO platform_users (username, password_hash, display_name) VALUES (?,?,?)')
        .run(username, bcrypt.hashSync(password, 12), displayName);
    } catch (err) {
      if (err && String(err.code || '').startsWith('SQLITE_CONSTRAINT')) {
        flash(req, 'error', 'That platform username is already taken.');
        return res.redirect('/platform/setup');
      }
      throw err;
    }
    audit(null, 'system', 'platform.admin_created',
      `Platform administrator account "${username}" created via /platform/setup (${allowed.keyRequired ? 'authorized by PLATFORM_OWNER_KEY' : 'open first-run on an empty instance'})`);
    flash(req, 'ok', 'Platform administrator account created. Sign in.');
    res.redirect('/platform');
  });

  /* ---------------- sign in / out ---------------- */

  router.post('/auth', (req, res) => {
    if (authLimiter.blocked(req)) {
      flash(req, 'error', 'Too many attempts from your connection. Wait a few minutes and try again.');
      return res.redirect('/platform');
    }
    const username = String(req.body.username || '').trim();
    const u = username ? db.prepare('SELECT * FROM platform_users WHERE username=?').get(username) : null;
    if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.password_hash)) {
      /* Submitted values are never recorded anywhere. */
      audit(null, 'system', 'platform.auth_failed', 'Failed platform-administrator sign-in attempt (submitted username not recorded)');
      flash(req, 'error', 'Sign-in failed. Check the username and password.');
      return res.redirect('/platform');
    }
    req.session.platform_admin = { id: u.id, username: u.username, name: u.display_name };
    audit(null, u.username, 'platform.auth', 'Platform administrator signed in');
    res.redirect('/platform');
  });

  router.post('/logout', (req, res) => {
    if (req.session) delete req.session.platform_admin;
    res.redirect('/platform');
  });

  /* ---------------- dashboard: per-local stats + rollup ---------------- */
  router.get('/', (req, res) => {
    if (!tenant.platformAdminExists()) return res.redirect('/platform/setup');
    const admin = currentPlatformAdmin(req);
    if (!admin) {
      return res.render('platform/login', { title: 'Platform administration' });
    }
    res.locals.platformAdmin = { id: admin.id, username: admin.username, name: admin.display_name };
    const locals = tenant.listLocals();
    res.render('platform/dashboard', {
      title: 'Platform administration',
      rollup: computeStats(null),
      perLocal: locals.map((l) => ({ local: l, stats: computeStats(l.id) })),
      localsCount: locals.length,
      jurisdictions: US_JURISDICTIONS,
      archives: listArchives(),
      archivesEncrypted: archiveEncryptionAvailable(),
      smtp: smtpConfigured(),
      resetTtlMinutes: RESET_TOKEN_TTL_MINUTES,
      platformEvents: db.prepare('SELECT id, at, actor, event, detail FROM audit_log WHERE local_id IS NULL ORDER BY id DESC LIMIT 50').all(),
    });
  });

  /* ---------------- create a local + its first committee admin ----------
   * The multi-local heir to the old one-time /setup: one transaction creates
   * the walled-off local and its very first committee-admin account. The
   * account is born INSIDE the new local — this flow cannot grant anyone
   * access to an existing local, and adding further accounts to a local is
   * the committee's own job (/admin/users). */
  router.post('/locals', requirePlatformAdmin, (req, res) => {
    const name = String(req.body.name || '').trim();
    const localNumber = String(req.body.local_number || '').trim();
    const jurisdiction = String(req.body.jurisdiction || '').trim().toUpperCase();
    const adminUsername = String(req.body.admin_username || '').trim();
    const adminPassword = String(req.body.admin_password || '');
    const adminDisplayName = String(req.body.admin_display_name || '').trim() || adminUsername;
    const adminEmail = String(req.body.admin_email || '').trim() || null;

    if (!name) { flash(req, 'error', 'The local needs a name (e.g. "IAFF Local 947 — Greensboro").'); return res.redirect('/platform'); }
    if (!JURISDICTION_CODES.has(jurisdiction)) { flash(req, 'error', 'Select the local\u2019s state/jurisdiction.'); return res.redirect('/platform'); }
    if (!adminUsername || adminPassword.length < 10) { flash(req, 'error', 'The first committee account needs a username and a password of at least 10 characters.'); return res.redirect('/platform'); }
    if (adminEmail) {
      const check = checkEmailSyntax(adminEmail);
      if (!check.ok) { flash(req, 'error', `Local not created. "${adminEmail}" does not look like a deliverable email address — ${check.reason}.`); return res.redirect('/platform'); }
    }

    let local;
    try {
      db.transaction(() => {
        local = tenant.createLocal({ name, localNumber: localNumber || null, jurisdiction });
        db.prepare('INSERT INTO users (local_id, username, password_hash, role, display_name, email) VALUES (?,?,?,?,?,?)')
          .run(local.id, adminUsername, bcrypt.hashSync(adminPassword, 12), 'admin', adminDisplayName, adminEmail);
      })();
    } catch (err) {
      if (err && String(err.code || '').startsWith('SQLITE_CONSTRAINT')) {
        flash(req, 'error', `The username "${adminUsername}" is already in use on this platform. Pick a different one (e.g. include the local number). No local was created.`);
        return res.redirect('/platform');
      }
      throw err;
    }

    /* First entry of the new local's own audit chain (its observers can see
     * where their tenancy came from), plus a platform-chain record. */
    audit(local.id, `platform:${req.platformAdmin.username}`, 'local.created',
      `Local "${name}"${localNumber ? ` (No. ${localNumber})` : ''} (jurisdiction ${jurisdiction}) created by the platform administrator; first committee-admin account "${adminUsername}" provisioned${adminEmail ? ' with a recovery email on file' : ''}`);
    audit(null, `platform:${req.platformAdmin.username}`, 'platform.local_created',
      `Local #${local.id} "${name}" (jurisdiction ${jurisdiction}) created with first committee-admin account "${adminUsername}"`);

    flash(req, 'ok', `Local "${name}" created. Hand its committee the sign-in URL (/login), the username "${adminUsername}", and the password you chose — and have them add a recovery email and their observer accounts under Accounts.`);
    res.redirect('/platform');
  });

  /* ---------------- download a sealed archive ---------------- */
  router.get('/archives/:id/download', requirePlatformAdmin, (req, res) => {
    const a = db.prepare('SELECT * FROM archives WHERE id=?').get(req.params.id);
    if (!a) return notFound(res);
    const filePath = archiveFilePath(a.filename);
    if (!fs.existsSync(filePath)) {
      flash(req, 'error', `The archive record exists but its file (${a.filename}) is missing from the data directory. Restore the data directory from a backup.`);
      return res.redirect('/platform');
    }
    /* Audited on the owning local's chain: its observers can see that the
     * platform handed the archive back. */
    audit(a.local_id ?? null, `platform:${req.platformAdmin.username}`, 'platform.archive_downloaded',
      `Sealed records archive #${a.id} (election #${a.election_id} "${a.election_title}", ${a.ballot_count} encrypted ballots, ${a.encrypted ? 'encrypted at rest' : 'plaintext JSON'}) downloaded by the platform administrator`);
    res.setHeader('Content-Type', a.encrypted ? 'application/octet-stream' : 'application/json');
    res.download(filePath, a.filename);
  });

  /* ---------------- one-time password-reset link ---------------- */
  router.post('/reset-link', requirePlatformAdmin, (req, res) => {
    const username = String(req.body.username || '').trim();
    const u = username
      ? db.prepare('SELECT u.*, l.name AS local_name FROM users u JOIN locals l ON l.id=u.local_id WHERE u.username=?').get(username)
      : null;
    if (!u) {
      /* Feedback is fine here (this caller is authenticated), but the
       * submitted value still stays out of the permanent log. */
      audit(null, `platform:${req.platformAdmin.username}`, 'platform.reset_link_rejected', 'One-time reset link requested for an unknown account (submitted name not recorded)');
      flash(req, 'error', 'No committee or observer account has that exact username. Ask the local to confirm it — usernames are case-sensitive.');
      return res.redirect('/platform');
    }
    const resetUrl = beginPasswordReset(u.id);
    audit(u.local_id, `platform:${req.platformAdmin.username}`, 'platform.reset_link_generated',
      `One-time password-reset link generated for account "${u.username}" by the platform administrator (token not recorded; single use; expires in ${RESET_TOKEN_TTL_MINUTES} minutes)`);
    res.render('platform/reset-link-once', {
      title: 'One-time reset link',
      account: { username: u.username, display_name: u.display_name, role: u.role, local_name: u.local_name },
      resetUrl,
      ttlMinutes: RESET_TOKEN_TTL_MINUTES,
    });
  });

  /* ---------------- encrypted whole-database backup ----------------
   * Spans EVERY local, so it is a platform power, not a committee one. Still
   * sealed under BACKUP_KEY and still free of key shares — no backup can
   * open a ballot. */
  router.get('/backup', requirePlatformAdmin, async (req, res, next) => {
    try {
      const buf = await createEncryptedBackup();
      const stamp = new Date().toISOString().replace(/[:.]/g, '-').replace('Z', '');
      audit(null, `platform:${req.platformAdmin.username}`, 'backup.exported',
        `Encrypted database backup downloaded (AES-256-GCM under BACKUP_KEY, ${buf.length} bytes). Contains no key shares and no plaintext election key.`);
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="union-ballot-backup-${stamp}.ubk"`);
      res.send(buf);
    } catch (err) {
      if (err && err.publicMessage) { flash(req, 'error', err.publicMessage); return res.redirect('/platform'); }
      next(err);
    }
  });

  return router;
};
