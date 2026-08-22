/**
 * routes/platform.js — Platform-owner page: aggregate stats and recovery.
 *
 * WHO THIS IS FOR: the operator who hosts Union Ballot instances for locals
 * (not the local's election committee, and not an observer). Two jobs:
 *
 *   1. SPONSOR-READY VOLUME STATS — counts only, never PII. Elections by
 *      status, test vs binding, ballots cast, turnout rates, roster size as
 *      a number. No names, no emails, no phone numbers, no member lists, no
 *      local contact info — nothing on this page identifies a person.
 *
 *   2. LOCAL RECOVERY — list and download the sealed records archives
 *      written automatically at tally (so a local that lost its login or its
 *      copy of the results can be handed its records back), and generate a
 *      one-time password-reset link for a committee account when the emailed
 *      flow is unavailable. Neither power can open a ballot: archives hold
 *      only encrypted ballots, and decryption still requires K of N
 *      keyholders. There is deliberately NO way here to read member data.
 *
 * ACCESS: gated by PLATFORM_OWNER_KEY — a strong secret supplied by
 * environment variable, never stored in the database. An ordinary committee
 * or observer session grants NOTHING here: the committee runs elections; the
 * platform owner supports the instance; the roles do not overlap. The key is
 * accepted from a login form (which sets a session flag only — the key
 * itself is never kept) or from an X-Platform-Key request header; both are
 * compared in constant time, and the submitted value is never logged or
 * audited. If the variable is unset (or too short to be a real secret) every
 * route here answers 404, indistinguishable from the feature not existing.
 *
 * MULTI-LOCAL NOTE: this instance serves ONE local today, so these numbers
 * describe one local. The metrics shape (per-election counts and rates,
 * archive metadata rows) is what future multi-local reporting would roll up
 * into unchanged — see the archives table comment in src/db.js.
 */
'use strict';

const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const { db, audit } = require('../db');
const { listArchives, archiveFilePath, archiveEncryptionAvailable } = require('../archives');
const { beginPasswordReset, RESET_TOKEN_TTL_MINUTES } = require('../reset-tokens');
const { makeRateLimiter } = require('../simple-rate-limit');
const { smtpConfigured } = require('../mailer');

/* A short key is not a gate. Below this length the feature stays disabled —
 * with a console warning so a truncated paste is diagnosable — rather than
 * pretending a guessable value protects anything. */
const MIN_KEY_LENGTH = 16;
const RAW_KEY = String(process.env.PLATFORM_OWNER_KEY || '').trim();
const PLATFORM_KEY = RAW_KEY.length >= MIN_KEY_LENGTH ? RAW_KEY : null;
if (RAW_KEY && !PLATFORM_KEY) {
  console.error(`PLATFORM_OWNER_KEY is set but shorter than ${MIN_KEY_LENGTH} characters, so the /platform page stays disabled. Use a long random secret, e.g. \`openssl rand -hex 32\`.`);
}

/** Constant-time comparison; hashing first makes unequal lengths safe. */
function keyMatches(supplied) {
  if (!PLATFORM_KEY) return false;
  const a = crypto.createHash('sha256').update(String(supplied || '')).digest();
  const b = crypto.createHash('sha256').update(PLATFORM_KEY).digest();
  return crypto.timingSafeEqual(a, b);
}

/**
 * Authenticated = a valid X-Platform-Key header on THIS request, or the
 * session flag set by the login form. Only the boolean flag lives in the
 * session — never the key — so nothing recoverable is ever at rest.
 * A committee/observer login (req.session.user) is deliberately irrelevant.
 */
function isPlatformOwner(req) {
  const header = req.get('x-platform-key');
  if (header && keyMatches(header)) return true;
  return req.session && req.session.platform_owner === true;
}

/* ------------------------- aggregate stats ------------------------- */
/* Counts only. No query in this section may select a name, an email, a
 * phone number, or any other per-person field. */

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

function computeStats() {
  const byStatus = { draft: 0, credentials_issued: 0, open: 0, closed: 0, tallied: 0 };
  for (const r of db.prepare('SELECT status, COUNT(*) AS n FROM elections GROUP BY status').all()) byStatus[r.status] = r.n;
  const totalElections = Object.values(byStatus).reduce((a, b) => a + b, 0);
  const testElections = db.prepare('SELECT COUNT(*) AS n FROM elections WHERE is_test=1').get().n;

  /* Ballots three ways: sealed rows stored (electronic), ballots counted in
   * tallied results (sum of results_json.ballots_cast), and paper ballots
   * recorded as received. */
  const sealedBallots = db.prepare('SELECT COUNT(*) AS n FROM ballots').get().n;
  const sealedBallotsTest = db.prepare('SELECT COUNT(*) AS n FROM ballots b JOIN elections e ON e.id=b.election_id WHERE e.is_test=1').get().n;
  let talliedBallots = 0;
  for (const r of db.prepare("SELECT results_json FROM elections WHERE status='tallied' AND results_json IS NOT NULL").all()) {
    try { talliedBallots += Number(JSON.parse(r.results_json).ballots_cast) || 0; } catch (_) { /* a malformed row must not break the stats page */ }
  }
  const paperBallots = db.prepare("SELECT COUNT(*) AS n FROM turnout WHERE method='paper'").get().n;

  const snapshotRows = db.prepare("SELECT id, is_test, eligibility_snapshot FROM elections WHERE eligibility_snapshot IS NOT NULL").all();
  return {
    elections: {
      total: totalElections,
      by_status: byStatus,
      completed: byStatus.tallied,
      in_preparation: byStatus.draft + byStatus.credentials_issued,
      test: testElections,
      binding: totalElections - testElections,
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
    roster_size: db.prepare('SELECT COUNT(*) AS n FROM members').get().n,
  };
}

module.exports = function platformRoutes({ flash }) {
  const router = express.Router();
  const authLimiter = makeRateLimiter({ windowMs: 15 * 60 * 1000, max: 20 });

  /* Unconfigured ⇒ the page does not exist. Same body as the app's 404. */
  function notFound(res) {
    return res.status(404).render('error', { title: 'Not found', message: 'That page does not exist.' });
  }

  router.use((req, res, next) => {
    if (!PLATFORM_KEY) return notFound(res);
    next();
  });

  function requireOwner(req, res, next) {
    if (!isPlatformOwner(req)) {
      flash(req, 'error', 'Enter the platform owner key first.');
      return res.redirect('/platform');
    }
    next();
  }

  /* ---------------- sign in / out ---------------- */
  router.post('/auth', (req, res) => {
    if (authLimiter.blocked(req)) {
      flash(req, 'error', 'Too many attempts from your connection. Wait a few minutes and try again.');
      return res.redirect('/platform');
    }
    if (!keyMatches(req.body.key)) {
      /* The submitted value is never recorded anywhere. */
      audit('system', 'platform.auth_failed', 'Failed platform-owner sign-in attempt (submitted key not recorded)');
      flash(req, 'error', 'That key was not recognized.');
      return res.redirect('/platform');
    }
    req.session.platform_owner = true; // flag only; the key is never stored
    audit('platform-owner', 'platform.auth', 'Platform owner signed in with PLATFORM_OWNER_KEY');
    res.redirect('/platform');
  });

  router.post('/logout', (req, res) => {
    if (req.session) delete req.session.platform_owner;
    res.redirect('/platform');
  });

  /* ---------------- stats + archives dashboard ---------------- */
  router.get('/', (req, res) => {
    if (!isPlatformOwner(req)) {
      return res.render('platform/login', { title: 'Platform owner' });
    }
    res.render('platform/dashboard', {
      title: 'Platform owner',
      stats: computeStats(),
      archives: listArchives(),
      archivesEncrypted: archiveEncryptionAvailable(),
      smtp: smtpConfigured(),
      resetTtlMinutes: RESET_TOKEN_TTL_MINUTES,
    });
  });

  /* ---------------- download a sealed archive ---------------- */
  router.get('/archives/:id/download', requireOwner, (req, res) => {
    const a = db.prepare('SELECT * FROM archives WHERE id=?').get(req.params.id);
    if (!a) return notFound(res);
    const filePath = archiveFilePath(a.filename);
    if (!fs.existsSync(filePath)) {
      flash(req, 'error', `The archive record exists but its file (${a.filename}) is missing from the data directory. Restore the data directory from a backup.`);
      return res.redirect('/platform');
    }
    audit('platform-owner', 'platform.archive_downloaded',
      `Sealed records archive #${a.id} (election #${a.election_id} "${a.election_title}", ${a.ballot_count} encrypted ballots, ${a.encrypted ? 'encrypted at rest' : 'plaintext JSON'}) downloaded by the platform owner`);
    res.setHeader('Content-Type', a.encrypted ? 'application/octet-stream' : 'application/json');
    res.download(filePath, a.filename);
  });

  /* ---------------- one-time password-reset link ---------------- */
  router.post('/reset-link', requireOwner, (req, res) => {
    const username = String(req.body.username || '').trim();
    const u = username ? db.prepare('SELECT * FROM users WHERE username=?').get(username) : null;
    if (!u) {
      /* Feedback is fine here (this caller is key-gated), but the submitted
       * value still stays out of the permanent log. */
      audit('platform-owner', 'platform.reset_link_rejected', 'One-time reset link requested for an unknown account (submitted name not recorded)');
      flash(req, 'error', 'No committee or observer account has that exact username. Ask the local to confirm it — usernames are case-sensitive.');
      return res.redirect('/platform');
    }
    const resetUrl = beginPasswordReset(u.id);
    audit('platform-owner', 'platform.reset_link_generated',
      `One-time password-reset link generated for account "${u.username}" by the platform owner (token not recorded; single use; expires in ${RESET_TOKEN_TTL_MINUTES} minutes)`);
    res.render('platform/reset-link-once', {
      title: 'One-time reset link',
      account: { username: u.username, display_name: u.display_name, role: u.role },
      resetUrl,
      ttlMinutes: RESET_TOKEN_TTL_MINUTES,
    });
  });

  return router;
};
