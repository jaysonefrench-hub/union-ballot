/**
 * routes/admin.js — Election-committee functions, for ONE local.
 *
 * Note what an administrator here can and cannot do:
 *   CAN:  manage the roster, configure votes, issue/void credentials,
 *         open/close voting, run the tally CEREMONY, export records —
 *         for their own local only.
 *   CANNOT: read any ballot. Ballots are sealed to the election public key;
 *         the private key exists only as Shamir shares held by keyholders
 *         (candidate representatives + a neutral). The tally requires K of N
 *         shares entered together, ideally with observers present.
 *   CANNOT: reach any other local. server.js mounts this router behind
 *         resolveLocal, so req.localId is the signed-in account's local, and
 *         every query below carries it (directly, or through an election row
 *         fetched with the local_id check). A guessed id from another local
 *         behaves exactly like an id that never existed.
 */
'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const { db, audit, getReissueKey, purgeReissueMap } = require('../db');
const {
  generateElectionKeys, combineShares, decryptBallot,
  generateCredential, hashCredential, aesEncrypt, aesDecrypt, randomHex, secureShuffle,
  generateVerifyToken, hashVerifyToken, zeroize,
} = require('../crypto');
const { smtpConfigured, sendCredentialEmail, sendVerificationEmail } = require('../mailer');
const { checkEmailSyntax } = require('../email-syntax');
const { buildArchive, writeSealedArchive } = require('../archives');
const {
  electionSkipsEmailVerify, markTestElectionBanner, demoSkipForCreate,
} = require('../election-demo');
const tenant = require('../tenant');
const { US_JURISDICTIONS, JURISDICTION_CODES } = require('../jurisdictions');

const BASE_URL = () => process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;

/**
 * Florida PERC hard stop: a BINDING electronic contract-ratification vote in
 * Florida is blocked unless the committee explicitly records that it holds a
 * current PERC variance for electronic ratification. FAC 60CC-4.002 requires
 * ratification by secret ballot at a meeting or by mail with a public count;
 * PERC has denied electronic-voting requests (e.g. the May 2022 denials), and
 * no general PERC approval of electronic ratification exists. Officer
 * elections, bylaws amendments, and every non-Florida jurisdiction are NOT
 * affected by this gate.
 */
function percRatificationBlocked({ jurisdiction, kind, isTest, varianceAck }) {
  return jurisdiction === 'FL' && kind === 'contract_ratification' && !isTest && !varianceAck;
}

const PERC_BLOCK_MESSAGE =
  'Blocked: a binding electronic contract-ratification vote for a Florida unit cannot be created here. '
  + 'Florida Administrative Code 60CC-4.002 requires ratification by secret ballot at a meeting or by mail ballot with a publicly announced count, '
  + 'and PERC has denied requests to conduct ratification electronically (May 2022 denials); there is no general PERC approval of electronic ratification voting. '
  + 'Use a meeting or mail ballot, mark this vote as a TEST election, or — only if your unit actually holds a current PERC variance permitting electronic ratification — '
  + 'check the variance acknowledgment on the form. This system does not verify or grant PERC approval.';

/**
 * Start (or restart) email verification for a member: a fresh single-use
 * token invalidates any previous one. Only the hash is stored; the plaintext
 * token exists in the returned URL only, for the email or one-time display.
 */
function beginEmailVerification(memberId) {
  const token = generateVerifyToken();
  db.prepare("UPDATE members SET email_verify_token_hash=?, email_verify_sent_at=datetime('now') WHERE id=?")
    .run(hashVerifyToken(token), memberId);
  return `${BASE_URL()}/verify-email?token=${token}`;
}

/** Election WITH its races/candidates — only if it belongs to this local
 * (throws a 404 otherwise; tenant.getElection carries the local_id check). */
function getElection(localId, id) {
  const e = tenant.getElection(localId, id);
  e.races = db.prepare('SELECT * FROM races WHERE election_id=? ORDER BY position, id').all(e.id);
  for (const r of e.races) r.candidates = db.prepare('SELECT * FROM candidates WHERE race_id=? ORDER BY position, id').all(r.id);
  return e;
}

/**
 * Split the good-standing roster into electronic vs paper for credential
 * issuance. Binding elections require email_verified=1. A TEST election with
 * demo_skip_email_verify=1 accepts syntactically valid emails even when
 * unverified. Paper (flagged, or no email) is unchanged either way.
 *
 * SCOPED TO THE ELECTION'S OWN LOCAL: eligibility is read from the election
 * row itself (not the session), so only members of the local that owns this
 * election can ever be swept into its credential issuance. An instance-wide
 * roster query here once pulled a stray pre-existing member from outside the
 * local into a new election's issuance — that class of bug is what the
 * local_id filter below exists to prevent.
 */
function listCredentialPaths(election) {
  const skipVerify = electionSkipsEmailVerify(election);
  const paper = db.prepare("SELECT * FROM members WHERE local_id=? AND good_standing=1 AND (needs_paper_ballot=1 OR email IS NULL OR email='') ORDER BY name").all(election.local_id);
  const withEmail = db.prepare("SELECT * FROM members WHERE local_id=? AND good_standing=1 AND needs_paper_ballot=0 AND email IS NOT NULL AND email!='' ORDER BY name").all(election.local_id);
  const electronic = [];
  const unverified = [];
  const invalidSyntax = [];
  for (const m of withEmail) {
    const check = checkEmailSyntax(m.email);
    if (!check.ok) {
      invalidSyntax.push(m);
      continue;
    }
    if (skipVerify || Number(m.email_verified) === 1) electronic.push(m);
    else unverified.push(m);
  }
  return { paper, electronic, unverified, invalidSyntax, skipVerify };
}

/** This member's entry in the election's FROZEN eligibility snapshot, or
 * null. The snapshot fixes both eligibility and voting method (electronic vs
 * paper) at credential issuance; the paper and reissue routes must consult
 * it, never the live roster. */
function snapshotEntry(election, memberId) {
  return JSON.parse(election.eligibility_snapshot || '[]')
    .find((s) => Number(s.member_id) === Number(memberId)) || null;
}

/**
 * Take the top `seatCount` entries from `qualified` (candidates that meet the
 * race's threshold, already sorted by votes descending) WITHOUT ever breaking
 * a tie by sort order. When the candidates at the final winning position have
 * equal votes, none of the tied candidates is declared for the contested
 * seat(s); the tie is returned so the caller can flag it for the committee to
 * resolve per the local's bylaws.
 */
function pickWinnersWithTies(qualified, seatCount) {
  if (qualified.length <= seatCount) return { winners: qualified.slice(), tie: null };
  const cutoff = qualified[seatCount - 1].votes;
  if (qualified[seatCount].votes === cutoff) {
    const sure = qualified.filter((s) => s.votes > cutoff);
    const tied = qualified.filter((s) => s.votes === cutoff);
    return { winners: sure, tie: { firstSeat: sure.length + 1, lastSeat: seatCount, between: tied.map((s) => s.name) } };
  }
  return { winners: qualified.slice(0, seatCount), tie: null };
}

/** "X and Y" / "X, Y and Z" for tie and runoff messages. */
function joinNames(names) {
  if (names.length <= 1) return names.join('');
  return names.slice(0, -1).join(', ') + ' and ' + names[names.length - 1];
}

/** "seat 2" / "seats 2 to 3" for tie messages. */
function seatLabel(firstSeat, lastSeat) {
  return firstSeat === lastSeat ? `seat ${lastSeat}` : `seats ${firstSeat} to ${lastSeat}`;
}

module.exports = function adminRoutes({ flash }) {
  const router = express.Router();

  /* ---------------- dashboard ---------------- */
  router.get('/', (req, res) => {
    const elections = db.prepare('SELECT * FROM elections WHERE local_id=? ORDER BY id DESC').all(req.localId);
    for (const e of elections) {
      e.turnout = db.prepare('SELECT COUNT(*) AS n FROM turnout WHERE election_id=?').get(e.id).n;
      e.eligible = JSON.parse(e.eligibility_snapshot || '[]').length;
    }
    const memberCount = db.prepare('SELECT COUNT(*) AS n FROM members WHERE local_id=?').get(req.localId).n;
    res.render('admin/dashboard', { title: 'Election committee', elections, memberCount, smtp: smtpConfigured() });
  });

  /* ---------------- members ---------------- */
  router.get('/members', (req, res) => {
    const members = db.prepare('SELECT * FROM members WHERE local_id=? ORDER BY name').all(req.localId);
    res.render('admin/members', { title: 'Member roster', members, smtp: smtpConfigured() });
  });

  router.post('/members/import', async (req, res, next) => {
    try {
      /*
       * EMAIL SYNTAX GATE (import): an address that cannot receive mail as
       * written (jane@gmail, jane@@x.com, "jane smith@…") would sit on the
       * roster as "Pending" forever — its verification link can never arrive.
       * So each row is checked BEFORE insert: valid rows import exactly as
       * before; rows with a malformed email (or no name) are NOT imported and
       * are reported back line-by-line with the reason, so the committee can
       * fix and re-import precisely those rows. An EMPTY email is never an
       * error — that member uses the paper-ballot path, unchanged. Whether a
       * well-formed address is real and the member's own is still proven only
       * by the magic-link verification flow.
       */
      const rawLines = String(req.body.roster || '').split(/\r?\n/);
      const valid = [];    // { name, email|null, num|null }
      const rejected = []; // { line, raw, name, email, reason }
      rawLines.forEach((rawLine, idx) => {
        const line = rawLine.trim();
        if (!line) return; // blank line — not data, nothing to report
        const [name, email, num] = line.split(',').map((s) => (s || '').trim());
        if (!name) {
          rejected.push({ line: idx + 1, raw: line, name: '', email: email || '', reason: 'missing the member name (format: Name, email, member number)' });
          return;
        }
        if (email) {
          const check = checkEmailSyntax(email);
          if (!check.ok) {
            rejected.push({ line: idx + 1, raw: line, name, email, reason: check.reason });
            return;
          }
        }
        valid.push({ name, email: email || null, num: num || null });
      });

      const ins = db.prepare('INSERT INTO members (local_id, name, email, member_number) VALUES (?,?,?,?)');
      const withEmail = []; // { id, name, email } — need verification before electronic delivery
      db.transaction(() => {
        for (const v of valid) {
          const info = ins.run(req.localId, v.name, v.email, v.num);
          if (v.email) withEmail.push({ id: info.lastInsertRowid, name: v.name, email: v.email });
        }
      })();
      const added = valid.length;
      /* Counts only in the audit log — the rejected addresses themselves are
       * shown to the committee on the report page, not written to the
       * observer-visible permanent record. */
      audit(req.localId, req.session.user.username, 'roster.import',
        `${added} members added to roster (${withEmail.length} with email, pending verification)`
        + (rejected.length ? `; ${rejected.length} row(s) NOT imported (invalid email syntax or missing name), reported to the committee for correction` : ''));

      /* Members with an email address start UNVERIFIED. If SMTP is configured,
       * send each a verification link now; otherwise they stay pending and the
       * committee sends links per member from the roster page. */
      let sent = 0; const failures = [];
      if (smtpConfigured() && withEmail.length > 0) {
        for (const m of withEmail) {
          const verifyUrl = beginEmailVerification(m.id);
          try {
            await sendVerificationEmail({ to: m.email, memberName: m.name, verifyUrl });
            sent++;
          } catch (err) { failures.push(`${m.name} <${m.email}>: ${err.message}`); }
        }
        audit(req.localId, req.session.user.username, 'roster.verification_emails_sent', `${sent} email-verification link(s) sent after import, ${failures.length} failed`);
      }

      /* Anything rejected → show the full report page (row/name/email/reason
       * plus a pre-filled fix-and-reimport form). Never silently drop a row,
       * and never fail the whole upload over a few bad addresses. */
      if (rejected.length > 0) {
        return res.render('admin/import-report', {
          title: 'Roster import report',
          added, rejected, sent, failures,
          withEmailCount: withEmail.length, smtp: smtpConfigured(),
        });
      }

      if (smtpConfigured() && withEmail.length > 0) {
        flash(req, failures.length ? 'error' : 'ok',
          `${added} member(s) added. Verification links emailed to ${sent} member(s)`
          + (failures.length ? `; ${failures.length} failed — use Resend on those rows.` : '. Electronic credentials can only be issued to verified addresses.'));
      } else {
        flash(req, 'ok', `${added} member(s) added.`
          + (withEmail.length ? ` ${withEmail.length} have an email address and must confirm it before electronic credentials can be issued${smtpConfigured() ? '' : ' (SMTP is not configured — use "Send link" on each row to get a one-time verification link for manual delivery)'}.` : ''));
      }
      res.redirect('/admin/members');
    } catch (err) { next(err); }
  });

  router.post('/members/:id/update', async (req, res, next) => {
    try {
      const m = tenant.getMember(req.localId, req.params.id);
      if (!m) return res.redirect('/admin/members');
      const good = req.body.good_standing === '1' ? 1 : 0;
      const paper = req.body.needs_paper_ballot === '1' ? 1 : 0;
      const newEmail = (req.body.email || '').trim() || null;
      /* Same syntax gate as import. The whole save is rejected (not partially
       * applied) so the committee never has to guess which fields took.
       * Clearing the email is always allowed — that is the paper path. */
      if (newEmail) {
        const check = checkEmailSyntax(newEmail);
        if (!check.ok) {
          flash(req, 'error',
            `Not saved. "${newEmail}" does not look like a deliverable email address — ${check.reason}. `
            + `Fix the address and save again, or clear the email field to move ${m.name} to the paper-ballot path.`);
          return res.redirect('/admin/members');
        }
      }
      const emailChanged = (newEmail || '') !== (m.email || '');
      /* m was fetched with the local check; AND local_id here is defense in
       * depth so this write can never widen past the local. */
      db.prepare('UPDATE members SET good_standing=?, needs_paper_ballot=?, email=? WHERE id=? AND local_id=?')
        .run(good, paper, newEmail, m.id, req.localId);
      /* A changed address is a NEW claim: any previous verification (and any
       * outstanding token) no longer proves anything about it. */
      if (emailChanged) {
        db.prepare('UPDATE members SET email_verified=0, email_verified_at=NULL, email_verify_token_hash=NULL, email_verify_sent_at=NULL WHERE id=? AND local_id=?').run(m.id, req.localId);
      }
      audit(req.localId, req.session.user.username, 'roster.update', `Member #${m.id} (${m.name}): good_standing=${good}, paper=${paper}${emailChanged ? '; email changed — verification reset' : ''}`);
      if (emailChanged && newEmail && smtpConfigured()) {
        const verifyUrl = beginEmailVerification(m.id);
        try {
          await sendVerificationEmail({ to: newEmail, memberName: m.name, verifyUrl });
          flash(req, 'ok', `Saved. ${m.name}'s email changed, so a new verification link was emailed to ${newEmail}.`);
        } catch (err) {
          flash(req, 'error', `Saved, but the verification email to ${newEmail} failed (${err.message}). Use Resend on the row.`);
        }
      } else if (emailChanged && newEmail) {
        flash(req, 'ok', `Saved. ${m.name}'s email changed and is unverified — send them a new verification link before issuing electronic credentials.`);
      }
      res.redirect('/admin/members');
    } catch (err) { next(err); }
  });

  /* ---------------- (re)send an email-verification link ---------------- */
  router.post('/members/:id/send-verification', async (req, res, next) => {
    try {
      const m = tenant.getMember(req.localId, req.params.id);
      if (!m) return res.redirect('/admin/members');
      if (!m.email) { flash(req, 'error', `${m.name} has no email address on the roster; they use the paper-ballot method.`); return res.redirect('/admin/members'); }
      if (m.email_verified) { flash(req, 'ok', `${m.name}'s email address is already verified.`); return res.redirect('/admin/members'); }

      const verifyUrl = beginEmailVerification(m.id);
      if (smtpConfigured()) {
        await sendVerificationEmail({ to: m.email, memberName: m.name, verifyUrl });
        audit(req.localId, req.session.user.username, 'roster.verification_email_sent', `Verification link (re)sent to member #${m.id} (${m.name}); any previous link is now invalid`);
        flash(req, 'ok', `Verification link emailed to ${m.name} <${m.email}>. Any earlier link no longer works.`);
        res.redirect('/admin/members');
      } else {
        /* No SMTP: show the link exactly once for manual delivery (same
         * pattern as the one-time credential export). */
        audit(req.localId, req.session.user.username, 'roster.verification_link_displayed', `One-time verification link displayed for member #${m.id} (${m.name}) for manual delivery; any previous link is now invalid`);
        res.render('admin/verify-link-once', { title: 'One-time verification link', m, verifyUrl });
      }
    } catch (err) { next(err); }
  });

  /* ---------------- create election + key ceremony ---------------- */
  router.get('/elections/new', (req, res) => {
    res.render('admin/election-new', {
      title: 'New vote',
      jurisdictions: US_JURISDICTIONS,
      /* Pre-select the local's own state; the committee can still override
       * per election (a unit may sit in a different jurisdiction). */
      defaultJurisdiction: req.local.jurisdiction || '',
    });
  });

  router.post('/elections/new', (req, res) => {
    const { title, kind, opens_at, closes_at, notice_sent_on } = req.body;
    const isTest = req.body.is_test === '1' ? 1 : 0;
    /* Binding votes can never store the bypass, even if the form posts it. */
    const demoSkip = demoSkipForCreate({ isTest, posted: req.body.demo_skip_email_verify });

    /* Jurisdiction is required so jurisdiction-specific legal gates can run. */
    const jurisdiction = String(req.body.jurisdiction || '').trim().toUpperCase();
    if (!JURISDICTION_CODES.has(jurisdiction)) {
      flash(req, 'error', 'Select the jurisdiction this bargaining unit / local operates in. It determines which legal requirements apply to the vote.');
      return res.redirect('/admin/elections/new');
    }

    /*
     * FLORIDA PERC HARD STOP (contract ratification only). See
     * percRatificationBlocked() for the legal basis. The checkbox records the
     * committee's own claim of a current PERC variance — this system never
     * asserts PERC (or OLMS) approval of anything.
     */
    const percAck = req.body.perc_variance_ack === '1' ? 1 : 0;
    const percRef = percAck ? String(req.body.perc_variance_ref || '').trim() : '';
    if (percRatificationBlocked({ jurisdiction, kind, isTest, varianceAck: percAck })) {
      audit(req.localId, req.session.user.username, 'election.create_blocked_perc',
        `Creation of a binding Florida electronic contract-ratification vote ("${String(title || '').trim()}") was blocked: no PERC variance acknowledgment recorded (FAC 60CC-4.002)`);
      flash(req, 'error', PERC_BLOCK_MESSAGE);
      return res.redirect('/admin/elections/new');
    }

    /*
     * IAFF Best Practices & Model Rules: matters requiring a secret ballot
     * under applicable law or the IAFF Constitution (officer elections,
     * delegate elections, dues rate adjustments) may only be voted
     * electronically after the Local obtains approval of the platform and
     * procedures from the IAFF Legal Department. A binding (non-test) vote
     * of these kinds requires the committee to record that approval.
     */
    const SECRET_BALLOT_KINDS = ['officer_election', 'delegate_election', 'dues_assessment'];
    const approvalRef = String(req.body.iaff_legal_approval || '').trim();
    if (SECRET_BALLOT_KINDS.includes(kind) && !isTest && !approvalRef) {
      flash(req, 'error', 'Officer elections, delegate elections, and dues votes require a secret ballot. Per the IAFF Best Practices & Model Rules, record the IAFF Legal Department\u2019s approval of this platform and your procedures (date/reference) before creating a binding vote \u2014 or mark this as a test election.');
      return res.redirect('/admin/elections/new');
    }
    const sharesTotal = Math.min(Math.max(Number(req.body.key_shares_total || 5), 2), 15);
    const threshold = Math.min(Math.max(Number(req.body.key_threshold || 3), 2), sharesTotal);
    const keyholders = String(req.body.keyholders || '').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);

    /* races arrive as parallel arrays */
    let raceTitles = req.body.race_title || [];
    let raceSeats = req.body.race_seats || [];
    let raceThresh = req.body.race_threshold || [];
    let raceCands = req.body.race_candidates || [];
    if (!Array.isArray(raceTitles)) { raceTitles = [raceTitles]; raceSeats = [raceSeats]; raceThresh = [raceThresh]; raceCands = [raceCands]; }

    if (!title || raceTitles.filter(Boolean).length === 0) {
      flash(req, 'error', 'A vote needs a title and at least one race or question.');
      return res.redirect('/admin/elections/new');
    }

    const keys = generateElectionKeys(sharesTotal, threshold);

    let electionId;
    db.transaction(() => {
      const info = db.prepare(`INSERT INTO elections
        (local_id, title, kind, jurisdiction, perc_variance_ack, perc_variance_ref, iaff_legal_approval, is_test, demo_skip_email_verify, status, notice_sent_on, opens_at, closes_at, public_key, key_shares_total, key_threshold, keyholders)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(req.localId, title.trim(), kind, jurisdiction, percAck, percRef || null, approvalRef || null, isTest, demoSkip, 'draft', notice_sent_on || null, opens_at || null, closes_at || null,
          keys.publicKey, sharesTotal, threshold, JSON.stringify(keyholders));
      electionId = info.lastInsertRowid;
      for (let i = 0; i < raceTitles.length; i++) {
        if (!raceTitles[i] || !raceTitles[i].trim()) continue;
        const r = db.prepare('INSERT INTO races (election_id, title, seats, threshold, position) VALUES (?,?,?,?,?)')
          .run(electionId, raceTitles[i].trim(), Math.max(1, Number(raceSeats[i] || 1)), raceThresh[i] || 'majority', i);
        const cands = String(raceCands[i] || '').split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
        cands.forEach((name, j) => db.prepare('INSERT INTO candidates (race_id, name, position) VALUES (?,?,?)').run(r.lastInsertRowid, name, j));
      }
    })();

    audit(req.localId, req.session.user.username, 'election.created',
      `Election #${electionId} "${title.trim()}" (${kind}${isTest ? ', TEST' : ''}, jurisdiction ${jurisdiction}) created; ballot key split ${threshold}-of-${sharesTotal}; keyholders: ${keyholders.join('; ') || 'not recorded'}${approvalRef ? `; IAFF Legal Dept approval recorded: ${approvalRef}` : ''}${percAck ? `; committee recorded its claim of a current Florida PERC variance for electronic ratification${percRef ? ` (ref: ${percRef})` : ''} — not verified by this system` : ''}${demoSkip ? '; DEMO skip-email-verify ON (TEST dry-run)' : ''}`);

    /* Shares are displayed exactly once and never stored. */
    if (isTest) markTestElectionBanner(res, { is_test: 1 });
    res.render('admin/shares-once', {
      title: 'Key ceremony — distribute these shares now',
      electionId, shares: keys.shares, threshold, keyholders,
    });
  });

  /* ---------------- election detail ---------------- */
  router.get('/elections/:id', (req, res) => {
    const e = getElection(req.localId, req.params.id);
    const credStats = db.prepare('SELECT COUNT(*) AS total, SUM(redeemed) AS used, SUM(voided) AS voided FROM credentials WHERE election_id=?').get(e.id);
    const ballotCount = db.prepare('SELECT COUNT(*) AS n FROM ballots WHERE election_id=?').get(e.id).n;
    const turnout = db.prepare(`SELECT m.name, t.voted_on, t.method FROM turnout t JOIN members m ON m.id=t.member_id WHERE t.election_id=? ORDER BY m.name`).all(e.id);
    const eligible = JSON.parse(e.eligibility_snapshot || '[]');
    const eligibleMembers = eligible.map((s) => {
      /* Snapshot ids are this election's own, but keep the local check anyway:
       * a name lookup must never cross into another local's roster. */
      const m = db.prepare('SELECT id, name, good_standing FROM members WHERE id=? AND local_id=?').get(s.member_id, req.localId);
      return { member_id: s.member_id, name: m ? m.name : `member #${s.member_id}`, method: s.method, good_standing: m ? Number(m.good_standing) : 0 };
    });
    const paths = listCredentialPaths(e);
    /* The paper-receipt list comes from the FROZEN eligibility snapshot
     * (method 'paper'), never the live roster: a member added or re-flagged
     * after credentials were issued is not eligible on this election's paper
     * path. Good standing is still read live so a suspended member drops off.
     * The server-side check in /paper-received enforces the same rule. */
    const paperMembers = eligibleMembers
      .filter((s) => s.method === 'paper' && s.good_standing === 1)
      .map((s) => ({ id: s.member_id, name: s.name }));
    /* Members who would block issuance (unverified on a vote that still
     * requires magic-link confirm). Empty when TEST + demo_skip is on. */
    const unverifiedMembers = paths.unverified;
    const demoUnverifiedMembers = paths.skipVerify
      ? paths.electronic.filter((m) => Number(m.email_verified) !== 1)
      : [];
    markTestElectionBanner(res, e);
    /* Reissue-map state: is the encrypted member<->credential map still present,
     * or has it already been purged? Drives the post-close purge control. */
    const rm = db.prepare("SELECT COUNT(*) AS total, SUM(CASE WHEN member_ref<>'' THEN 1 ELSE 0 END) AS present FROM credentials WHERE election_id=?").get(e.id);
    const reissueMapPresent = (rm.present || 0) > 0;
    const reissueMapPurged = rm.total > 0 && (rm.present || 0) === 0;
    res.render('admin/election-detail', {
      title: e.title, e, credStats, ballotCount, turnout, eligibleCount: eligible.length, eligibleMembers,
      paperMembers, unverifiedMembers, demoUnverifiedMembers, skipEmailVerify: paths.skipVerify,
      smtp: smtpConfigured(), reissueMapPresent, reissueMapPurged,
      results: e.results_json ? JSON.parse(e.results_json) : null,
    });
  });

  /* ---------------- DEMO skip-email-verify toggle (TEST elections only) ---- */
  router.post('/elections/:id/demo-skip-email-verify', (req, res) => {
    const e = getElection(req.localId, req.params.id);
    if (!e.is_test) {
      audit(req.localId, req.session.user.username, 'election.demo_skip_blocked',
        `Election #${e.id} "${e.title}": refused to set demo_skip_email_verify — binding elections must require magic-link email verification`);
      flash(req, 'error', 'DEMO email-verify skip can only be set on TEST elections. Binding elections always require magic-link email verification.');
      return res.redirect(`/admin/elections/${e.id}`);
    }
    const next = req.body.demo_skip_email_verify === '1' ? 1 : 0;
    /* AND is_test=1 is defense in depth: a binding row can never store a 1.
     * AND local_id likewise: this write can never widen past the local. */
    db.prepare('UPDATE elections SET demo_skip_email_verify=? WHERE id=? AND is_test=1 AND local_id=?').run(next, e.id, req.localId);
    audit(req.localId, req.session.user.username, 'election.demo_skip_email_verify',
      `Election #${e.id} "${e.title}": demo_skip_email_verify set to ${next} (TEST dry-run ${next ? 'ON — unverified syntactically-valid emails eligible for electronic credentials' : 'OFF — magic-link verification required'})`);
    flash(req, 'ok', next
      ? 'DEMO skip-email-verify is ON for this TEST election. Electronic credentials can be issued to syntactically valid addresses without a magic-link confirm.'
      : 'DEMO skip-email-verify is OFF. This TEST election now requires email verification before electronic credentials, same as a binding vote.');
    res.redirect(`/admin/elections/${e.id}`);
  });

  /* ---------------- issue credentials ---------------- */
  router.post('/elections/:id/issue-credentials', async (req, res, next) => {
    try {
      const e = getElection(req.localId, req.params.id);
      if (e.status !== 'draft') { flash(req, 'error', 'Credentials were already issued for this vote.'); return res.redirect(`/admin/elections/${e.id}`); }
      if (percRatificationBlocked({ jurisdiction: e.jurisdiction, kind: e.kind, isTest: e.is_test, varianceAck: e.perc_variance_ack })) {
        audit(req.localId, req.session.user.username, 'election.credential_issue_blocked_perc',
          `Election #${e.id} "${e.title}": credential issuance blocked — binding Florida electronic contract ratification without a recorded PERC variance acknowledgment (FAC 60CC-4.002)`);
        flash(req, 'error', PERC_BLOCK_MESSAGE);
        return res.redirect(`/admin/elections/${e.id}`);
      }

      /*
       * EMAIL VERIFICATION GATE: on a binding election, electronic credentials
       * go only to VERIFIED addresses. A TEST election with
       * demo_skip_email_verify=1 may issue to syntactically valid emails even
       * when email_verified=0 (dry-run without SMTP / magic-link). Binding
       * votes never take that path. Paper (flagged, or no email) is unchanged
       * — no verification is required to receive a paper ballot. If anyone is
       * headed for the electronic path but cannot be issued (unverified on a
       * gated vote, or an address that fails syntax), refuse rather than
       * silently dropping them from both paths.
       */
      const { electronic, paper, unverified, invalidSyntax, skipVerify } = listCredentialPaths(e);
      if (invalidSyntax.length > 0) {
        audit(req.localId, req.session.user.username, 'election.credential_issue_blocked_email_syntax',
          `Election #${e.id}: credential issuance blocked — ${invalidSyntax.length} member(s) on the electronic path have an address that fails syntax validation`);
        const names = invalidSyntax.slice(0, 5).map((m) => m.name).join(', ');
        flash(req, 'error',
          `Cannot issue electronic credentials: ${invalidSyntax.length} member(s) have an email that is not syntactically valid `
          + `(${names}${invalidSyntax.length > 5 ? ', …' : ''}). `
          + 'Fix the address on the roster page, or flag them for a paper ballot.');
        return res.redirect(`/admin/elections/${e.id}`);
      }
      if (unverified.length > 0) {
        audit(req.localId, req.session.user.username, 'election.credential_issue_blocked_unverified',
          `Election #${e.id}: credential issuance blocked — ${unverified.length} member(s) on the electronic path have unverified email addresses`);
        const names = unverified.slice(0, 5).map((m) => m.name).join(', ');
        flash(req, 'error',
          `Cannot issue electronic credentials: ${unverified.length} member(s) have not confirmed their email address `
          + `(${names}${unverified.length > 5 ? ', …' : ''}). `
          + 'On the roster page, resend their verification links, or flag them for a paper ballot. Verified members and paper-ballot members are unaffected.');
        return res.redirect(`/admin/elections/${e.id}`);
      }
      if (electronic.length + paper.length === 0) { flash(req, 'error', 'The roster has no members in good standing. Import the roster first.'); return res.redirect(`/admin/elections/${e.id}`); }

      const reissueKey = getReissueKey();
      const issued = []; // { member, credential } — exists in memory only

      db.transaction(() => {
        for (const m of electronic) {
          const credential = generateCredential();
          const salt = randomHex(16);
          db.prepare('INSERT INTO credentials (election_id, code_hash, salt, member_ref) VALUES (?,?,?,?)')
            .run(e.id, hashCredential(credential, salt), salt, aesEncrypt(String(m.id), reissueKey));
          issued.push({ member: m, credential });
        }
        const snapshot = [
          ...electronic.map((m) => ({ member_id: m.id, method: 'electronic' })),
          ...paper.map((m) => ({ member_id: m.id, method: 'paper' })),
        ];
        db.prepare("UPDATE elections SET status='credentials_issued', eligibility_snapshot=? WHERE id=? AND local_id=?")
          .run(JSON.stringify(snapshot), e.id, req.localId);
      })();

      audit(req.localId, req.session.user.username, 'election.credentials_issued',
        `Election #${e.id}: ${issued.length} electronic credentials generated (random, hashed at rest); ${paper.length} member(s) flagged for the alternative paper-ballot method${skipVerify ? '; DEMO skip-email-verify ON (unverified syntactically-valid emails included)' : ''}`);

      /* Deliver */
      const voteUrl = (process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`) + '/';
      if (smtpConfigured() && req.body.delivery !== 'export') {
        let sent = 0; const failures = [];
        for (const { member, credential } of issued) {
          try {
            await sendCredentialEmail({ to: member.email, memberName: member.name, electionTitle: e.title, credential, voteUrl, closesAt: e.closes_at });
            sent++;
          } catch (err) { failures.push(`${member.name} <${member.email}>: ${err.message}`); }
        }
        audit(req.localId, req.session.user.username, 'election.credentials_emailed', `Election #${e.id}: ${sent} credential emails sent, ${failures.length} failed`);
        markTestElectionBanner(res, e);
        res.render('admin/credentials-sent', { title: 'Credentials emailed', e, sent, failures, paper });
      } else {
        /* One-time export for mail-merge; shown once, never retrievable again. */
        audit(req.localId, req.session.user.username, 'election.credentials_exported', `Election #${e.id}: one-time credential export displayed for mail-merge delivery`);
        markTestElectionBanner(res, e);
        res.render('admin/credentials-export', { title: 'One-time credential export', e, issued, paper, voteUrl });
      }
    } catch (err) { next(err); }
  });

  /* ---------------- reissue a lost credential ---------------- */
  router.post('/elections/:id/reissue', async (req, res, next) => {
    try {
      const e = getElection(req.localId, req.params.id);
      const memberId = Number(req.body.member_id);
      /* Tenant check on the member too: a posted id from another local's
       * roster must behave exactly like a member that does not exist. */
      const member = tenant.getMember(req.localId, memberId);
      if (!member || !['credentials_issued', 'open'].includes(e.status)) { flash(req, 'error', 'Reissue is only possible after credentials are issued and before the vote closes.'); return res.redirect(`/admin/elections/${e.id}`); }

      /*
       * FROZEN ELIGIBILITY (server side, mirroring the paper route): a
       * credential may only be reissued to a member recorded on the
       * ELECTRONIC path in this election's frozen eligibility snapshot and
       * still in good standing. The page hides everyone else, but hiding is
       * not enforcement; a posted id must be rejected here.
       */
      const snap = snapshotEntry(e, memberId);
      if (!snap || snap.method !== 'electronic') {
        audit(req.localId, req.session.user.username, 'election.reissue_blocked',
          `Election #${e.id}: reissue for member #${memberId} blocked: ${snap ? 'the member is on the paper-ballot path in the frozen eligibility snapshot' : 'the member is not in the frozen eligibility snapshot for this election'}`);
        flash(req, 'error', snap
          ? `${member.name} is on the paper-ballot path for this vote and cannot be issued an electronic credential.`
          : `${member.name} is not in the frozen eligibility list for this vote (eligibility was fixed when credentials were issued), so no credential can be issued.`);
        return res.redirect(`/admin/elections/${e.id}`);
      }
      if (Number(member.good_standing) !== 1) {
        audit(req.localId, req.session.user.username, 'election.reissue_blocked',
          `Election #${e.id}: reissue for member #${memberId} blocked: the member is not in good standing`);
        flash(req, 'error', `${member.name} is not in good standing; no replacement credential was issued.`);
        return res.redirect(`/admin/elections/${e.id}`);
      }
      /* A member already on the turnout list (for example a recorded paper
       * ballot) has voted; issuing them a fresh electronic credential would
       * open a second vote. */
      const alreadyVoted = db.prepare('SELECT method FROM turnout WHERE election_id=? AND member_id=?').get(e.id, memberId);
      if (alreadyVoted) {
        audit(req.localId, req.session.user.username, 'election.reissue_blocked',
          `Election #${e.id}: reissue for member #${memberId} blocked: the member is already recorded as having voted (${alreadyVoted.method})`);
        flash(req, 'error', `${member.name} is already recorded as having voted (${alreadyVoted.method === 'paper' ? 'paper ballot received' : 'electronically'}); no replacement credential can be issued. If the member disputes this, treat it as a security incident.`);
        return res.redirect(`/admin/elections/${e.id}`);
      }

      const reissueKey = getReissueKey();
      const rows = db.prepare('SELECT * FROM credentials WHERE election_id=? AND voided=0').all(e.id);
      const own = rows.find((c) => { try { return Number(aesDecrypt(c.member_ref, reissueKey)) === memberId; } catch { return false; } });
      if (own && own.redeemed) { flash(req, 'error', `${member.name}'s credential was already used to cast a ballot; it cannot be reissued. If the member disputes this, treat it as a security incident.`); audit(req.localId, req.session.user.username, 'election.reissue_blocked', `Election #${e.id}: reissue for member #${memberId} blocked — credential already redeemed`); return res.redirect(`/admin/elections/${e.id}`); }

      const credential = generateCredential();
      const salt = randomHex(16);
      db.transaction(() => {
        if (own) db.prepare('UPDATE credentials SET voided=1 WHERE id=?').run(own.id);
        db.prepare('INSERT INTO credentials (election_id, code_hash, salt, member_ref) VALUES (?,?,?,?)')
          .run(e.id, hashCredential(credential, salt), salt, aesEncrypt(String(memberId), reissueKey));
      })();
      audit(req.localId, req.session.user.username, 'election.credential_reissued', `Election #${e.id}: credential voided and reissued for one member (old credential invalidated)`);

      const voteUrl = (process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`) + '/';
      /* Email delivery only to a still-verified address (it may have been
       * changed since issuance), or to a syntactically valid address on a
       * TEST election with demo_skip_email_verify. Otherwise the one-time display. */
      const emailOk = !!(member.email && checkEmailSyntax(member.email).ok);
      const canEmailCred = smtpConfigured() && emailOk && (member.email_verified || electionSkipsEmailVerify(e));
      if (canEmailCred) {
        await sendCredentialEmail({ to: member.email, memberName: member.name, electionTitle: e.title, credential, voteUrl, closesAt: e.closes_at });
        flash(req, 'ok', `A replacement credential was emailed to ${member.name}. The previous credential no longer works.`);
        res.redirect(`/admin/elections/${e.id}`);
      } else {
        markTestElectionBanner(res, e);
        res.render('admin/credentials-export', { title: 'Replacement credential (shown once)', e, issued: [{ member, credential }], paper: [], voteUrl });
      }
    } catch (err) { next(err); }
  });

  /* ---------------- open / close ---------------- */
  router.post('/elections/:id/open', (req, res) => {
    const e = getElection(req.localId, req.params.id);
    if (e.status !== 'credentials_issued') { flash(req, 'error', 'Issue credentials before opening the vote.'); return res.redirect(`/admin/elections/${e.id}`); }
    /* Defense in depth: the Florida PERC ratification gate also holds at open,
     * covering elections created before this gate existed (or edited rows). */
    if (percRatificationBlocked({ jurisdiction: e.jurisdiction, kind: e.kind, isTest: e.is_test, varianceAck: e.perc_variance_ack })) {
      audit(req.localId, req.session.user.username, 'election.open_blocked_perc',
        `Election #${e.id} "${e.title}": opening blocked — binding Florida electronic contract ratification without a recorded PERC variance acknowledgment (FAC 60CC-4.002)`);
      flash(req, 'error', PERC_BLOCK_MESSAGE);
      return res.redirect(`/admin/elections/${e.id}`);
    }
    db.prepare("UPDATE elections SET status='open' WHERE id=? AND local_id=?").run(e.id, req.localId);
    audit(req.localId, req.session.user.username, 'election.opened', `Election #${e.id} "${e.title}" opened for voting`);
    flash(req, 'ok', 'Voting is open.');
    res.redirect(`/admin/elections/${e.id}`);
  });

  router.post('/elections/:id/close', (req, res) => {
    const e = getElection(req.localId, req.params.id);
    if (e.status !== 'open') { flash(req, 'error', 'Only an open vote can be closed.'); return res.redirect(`/admin/elections/${e.id}`); }
    db.prepare("UPDATE elections SET status='closed' WHERE id=? AND local_id=?").run(e.id, req.localId);
    audit(req.localId, req.session.user.username, 'election.closed', `Election #${e.id} "${e.title}" closed to voting`);
    flash(req, 'ok', 'Voting is closed. The ballots remain sealed until the tally ceremony.');
    res.redirect(`/admin/elections/${e.id}`);
  });

  /* ---------------- purge the reissue map (after close) ----------------
   * Destroys the encrypted member<->credential map once voting is closed, so
   * a stolen database plus a stolen REISSUE_KEY can no longer link any member
   * to their credential. Reissuing a lost credential is impossible after close,
   * so the map has no remaining purpose. The hashed credentials, turnout list,
   * sealed ballots, and audit log are all retained for the one-year record.
   * purgeReissueMap() itself refuses to run while voting is open. */
  router.post('/elections/:id/purge-reissue-map', (req, res, next) => {
    try {
      const e = getElection(req.localId, req.params.id);
      if (!['closed', 'tallied'].includes(e.status)) {
        flash(req, 'error', 'Close voting before purging the reissue map.');
        return res.redirect(`/admin/elections/${e.id}`);
      }
      const cleared = purgeReissueMap(e.id, req.localId);
      audit(req.localId, req.session.user.username, 'election.reissue_map_purged',
        `Election #${e.id} "${e.title}": member<->credential reissue map destroyed after close (${cleared} credential record(s) cleared). Hashed credentials, turnout, sealed ballots, and audit log retained.`);
      flash(req, 'ok', cleared > 0
        ? `Reissue map destroyed — ${cleared} record(s) cleared. The stored name-to-credential link no longer exists for this election.`
        : 'The reissue map was already empty for this election; nothing to purge.');
      res.redirect(`/admin/elections/${e.id}`);
    } catch (err) {
      /* purgeReissueMap throws with a publicMessage if voting is still open.
       * A tenant not-found (err.status 404 — another local's election id)
       * must fall through to the error handler and render as nonexistent. */
      if (err && err.publicMessage && !err.status) { flash(req, 'error', err.publicMessage); return res.redirect(`/admin/elections/${req.params.id}`); }
      next(err);
    }
  });

  /* ---------------- record a paper ballot received ---------------- */
  router.post('/elections/:id/paper-received', (req, res) => {
    const e = getElection(req.localId, req.params.id);
    const memberId = Number(req.body.member_id);
    if (!['open', 'closed'].includes(e.status)) { flash(req, 'error', 'Paper ballots can be recorded while the vote is open or closed (before tally).'); return res.redirect(`/admin/elections/${e.id}`); }
    /* The member must belong to this local — a foreign id must never land on
     * this election's turnout list. */
    const member = tenant.getMember(req.localId, memberId);
    if (!member) {
      flash(req, 'error', 'That member is not on this local\u2019s roster; no paper ballot was recorded.');
      return res.redirect(`/admin/elections/${e.id}`);
    }

    /*
     * FROZEN ELIGIBILITY: a paper ballot is accepted only from a member
     * recorded on the PAPER path in this election's eligibility snapshot
     * (frozen at credential issuance) who is still in good standing. The
     * live roster is deliberately not consulted for eligibility: a member
     * added or re-flagged after the freeze is not eligible on this path,
     * and a member issued an electronic credential uses void-and-reissue.
     */
    const snap = snapshotEntry(e, memberId);
    if (!snap || snap.method !== 'paper') {
      audit(req.localId, req.session.user.username, 'election.paper_ballot_refused',
        `Election #${e.id}: paper ballot for member #${memberId} refused: ${snap ? 'the member is on the electronic path in the frozen eligibility snapshot' : 'the member is not in the frozen eligibility snapshot for this election'}`);
      flash(req, 'error', snap
        ? `${member.name} was issued an electronic credential for this vote and is not on the paper-ballot list. No paper ballot was recorded. If their credential was lost, use void and reissue instead.`
        : `${member.name} is not in the frozen eligibility list for this vote (eligibility was fixed when credentials were issued). No paper ballot was recorded.`);
      return res.redirect(`/admin/elections/${e.id}`);
    }
    if (Number(member.good_standing) !== 1) {
      audit(req.localId, req.session.user.username, 'election.paper_ballot_refused',
        `Election #${e.id}: paper ballot for member #${memberId} refused: the member is not in good standing`);
      flash(req, 'error', `${member.name} is not in good standing. No paper ballot was recorded.`);
      return res.redirect(`/admin/elections/${e.id}`);
    }

    /* Any live electronic credential held by this member (none is issued on
     * the paper path, but one can exist in data predating the frozen-path
     * enforcement, for example an old reissue). Same lookup as /reissue.
     * Skipped entirely when no decryptable credential exists, so a purged
     * reissue map or a paper-only election never needs the reissue key. */
    let ownCredential = null;
    const liveCreds = db.prepare("SELECT id, member_ref, redeemed FROM credentials WHERE election_id=? AND voided=0 AND member_ref<>''").all(e.id);
    if (liveCreds.length > 0) {
      const reissueKey = getReissueKey();
      ownCredential = liveCreds.find((c) => { try { return Number(aesDecrypt(c.member_ref, reissueKey)) === memberId; } catch { return false; } }) || null;
    }

    /*
     * DOUBLE-VOTE GUARD: a member already recorded as having voted must be
     * refused LOUDLY. The old INSERT OR IGNORE silently skipped the write
     * and still told the committee "recorded", which would have let a paper
     * ballot from a member who already voted electronically be hand-counted
     * on top of their electronic ballot.
     */
    const already = db.prepare('SELECT method FROM turnout WHERE election_id=? AND member_id=?').get(e.id, memberId);
    if ((already && already.method === 'electronic') || (ownCredential && ownCredential.redeemed)) {
      audit(req.localId, req.session.user.username, 'election.paper_ballot_refused',
        `Election #${e.id}: paper ballot for member #${memberId} refused: the member already voted electronically. This paper ballot must NOT be counted.`);
      flash(req, 'error', `${member.name} already voted electronically in this vote: do not count this paper ballot. No paper receipt was recorded. If the member disputes having voted, treat this as a security incident and check the audit log.`);
      return res.redirect(`/admin/elections/${e.id}`);
    }
    if (already) {
      audit(req.localId, req.session.user.username, 'election.paper_ballot_refused',
        `Election #${e.id}: paper ballot for member #${memberId} refused: a paper ballot from this member was already recorded. A second paper ballot must NOT be counted.`);
      flash(req, 'error', `A paper ballot from ${member.name} was already recorded for this vote: do not count a second paper ballot from this member.`);
      return res.redirect(`/admin/elections/${e.id}`);
    }

    /*
     * Receipt and credential voiding are ONE transaction: the member is
     * marked as voted and loses any unused electronic credential atomically,
     * so no ordering of paper receipt and online casting can produce two
     * counted ballots. The turnout INSERT is plain (never OR IGNORE): the
     * guard above already refused an existing row, so a conflict here must
     * roll the whole receipt back rather than pass silently.
     */
    db.transaction(() => {
      if (ownCredential) db.prepare('UPDATE credentials SET voided=1 WHERE id=? AND redeemed=0').run(ownCredential.id);
      db.prepare('INSERT INTO turnout (election_id, member_id, voted_on, method) VALUES (?,?,date(\'now\'),\'paper\')').run(e.id, memberId);
    })();
    audit(req.localId, req.session.user.username, 'election.paper_ballot_received',
      `Election #${e.id}: a sealed paper ballot was logged as received (member marked as voted${ownCredential ? '; the member\u2019s unused electronic credential was voided in the same transaction' : ''})`);
    flash(req, 'ok', `Paper ballot receipt recorded.${ownCredential ? ` ${member.name}\u2019s unused electronic credential was voided and can no longer cast a ballot.` : ''} Count paper ballots with observers present and add them to the electronic results.`);
    res.redirect(`/admin/elections/${e.id}`);
  });

  /* ---------------- tally ceremony ---------------- */
  router.get('/elections/:id/tally', (req, res) => {
    const e = getElection(req.localId, req.params.id);
    if (e.status !== 'closed') { flash(req, 'error', 'Close the vote before tallying.'); return res.redirect(`/admin/elections/${e.id}`); }
    markTestElectionBanner(res, e);
    res.render('admin/tally', { title: 'Tally ceremony', e });
  });

  router.post('/elections/:id/tally', (req, res, next) => {
    try {
      const e = getElection(req.localId, req.params.id);
      if (e.status !== 'closed') { flash(req, 'error', 'Close the vote before tallying.'); return res.redirect(`/admin/elections/${e.id}`); }

      let shares = req.body.share || [];
      if (!Array.isArray(shares)) shares = [shares];
      shares = shares.map((s) => s.trim()).filter(Boolean);
      if (shares.length < e.key_threshold) {
        flash(req, 'error', `This election requires ${e.key_threshold} key shares to unseal the ballots. ${shares.length} provided.`);
        return res.redirect(`/admin/elections/${e.id}/tally`);
      }

      let privateKey;
      try {
        privateKey = combineShares(shares.slice(0, e.key_threshold));
      } catch (err) {
        audit(req.localId, req.session.user.username, 'tally.key_reconstruction_failed', `Election #${e.id}: key share combination failed — ${err.message}`);
        flash(req, 'error', err.message);
        return res.redirect(`/admin/elections/${e.id}/tally`);
      }

      const rows = db.prepare('SELECT payload FROM ballots WHERE election_id=?').all(e.id);
      /* Integrity check: sealed ballots must equal redeemed credentials. */
      const redeemed = db.prepare('SELECT COUNT(*) AS n FROM credentials WHERE election_id=? AND redeemed=1').get(e.id).n;
      if (rows.length !== redeemed) {
        audit(req.localId, req.session.user.username, 'tally.INTEGRITY_ALERT', `Election #${e.id}: ballot count (${rows.length}) does not match redeemed credentials (${redeemed}) — investigate before certifying`);
      }

      /* Shuffle before decrypting so even the ceremony reveals no order. */
      const shuffled = secureShuffle(rows);
      const ballots = [];
      let failed = 0;
      for (const row of shuffled) {
        try { ballots.push(decryptBallot(row.payload, privateKey)); } catch { failed++; }
      }
      /* Decryption was the key's only job. Wipe the reconstructed private
       * key buffer NOW, per the combineShares() caller contract, before any
       * counting, rendering, or early return can widen its lifetime. */
      zeroize(privateKey);
      if (failed > 0 && ballots.length === 0) {
        audit(req.localId, req.session.user.username, 'tally.decrypt_failed', `Election #${e.id}: ballots failed to decrypt — wrong shares or tampering`);
        flash(req, 'error', 'The ballots did not decrypt. Verify each keyholder pasted their full share for THIS election.');
        return res.redirect(`/admin/elections/${e.id}/tally`);
      }

      /* Count — PUBLISH PER-RACE AGGREGATES ONLY.
       *
       * GUARDRAIL (do not remove): results are tabulated one race at a time
       * into per-candidate totals. The decrypted `ballots` array lives only in
       * memory for this loop and is never persisted or rendered. Never add a
       * ballot-by-ballot listing, or any per-voter record of how one member
       * voted across races, to `results`, to the views, or to the archive:
       * publishing the full slate on any single ballot would enable coercion by
       * a unique-pattern ("Italian") attack, where a coercer assigns a member a
       * distinctive combination and then confirms it in the output. Aggregates
       * only, always. */
      const results = { races: [], ballots_cast: ballots.length, failed_decrypts: failed, redeemed_credentials: redeemed, integrity_ok: rows.length === redeemed && failed === 0 };
      /* Below this many ballots in a race, the totals themselves can expose how
       * individuals voted; we FLAG such a race rather than imply the seal hides
       * it. Override per local with SECRECY_MIN_BALLOTS if a different floor is
       * appropriate. */
      const SECRECY_MIN_BALLOTS = Math.max(2, Number(process.env.SECRECY_MIN_BALLOTS || 5));
      for (const race of e.races) {
        const counts = new Map(race.candidates.map((c) => [c.id, 0]));
        let ballotsInRace = 0; let totalVotes = 0;
        for (const b of ballots) {
          const picks = (b.choices && b.choices[race.id]) || [];
          const valid = picks.filter((id) => counts.has(id));
          if (valid.length > 0) ballotsInRace++;
          for (const id of valid) { counts.set(id, counts.get(id) + 1); totalVotes++; }
        }
        const standings = race.candidates
          .map((c) => ({ id: c.id, name: c.name, votes: counts.get(c.id) }))
          .sort((a, b) => b.votes - a.votes);

        /*
         * Thresholds:
         *  - majority, 1 seat (IAFF sample CBL): winner needs a majority of
         *    ballots cast in the race; otherwise runoff between top two.
         *  - majority, multi-seat: majority = totalVotes / (2 x seats)
         *    (the standard union election-manual method). Seats no candidate
         *    reached a majority for go to a runoff among the top non-winning
         *    candidates, up to two per unfilled seat (IAFF-style), with ties
         *    at that cutoff included.
         *  - two_thirds (bylaw amendments): top option needs >= 2/3 of
         *    ballots cast in the question.
         *  - plurality: top N win.
         *
         * TIE SAFETY (all modes): a tie at the winning cutoff (the last
         * seat, or the runoff cutoff) is NEVER broken silently by sort
         * order. The tied candidates are excluded from `winners`, and a
         * plain-language flag is recorded on the result itself, so it also
         * shows on the results pages and lands in the records archive, for
         * the committee to resolve per the local's bylaws.
         */
        let winners = []; let runoffRequired = false; let runoffBetween = []; let runoffSeats = 0;
        const tieFlags = [];
        if (race.threshold === 'plurality') {
          const qualified = standings.filter((s) => s.votes > 0);
          const picked = pickWinnersWithTies(qualified, race.seats);
          winners = picked.winners.map((s) => s.name);
          if (picked.tie) {
            tieFlags.push(`Tie for ${seatLabel(picked.tie.firstSeat, picked.tie.lastSeat)} between ${joinNames(picked.tie.between)}, resolve per your bylaws.`);
          }
        } else if (race.threshold === 'two_thirds') {
          const qualified = ballotsInRace > 0 ? standings.filter((s) => s.votes >= (2 / 3) * ballotsInRace) : [];
          const picked = pickWinnersWithTies(qualified, 1);
          winners = picked.winners.map((s) => s.name);
          if (picked.tie) {
            tieFlags.push(`Tie at the two-thirds threshold between ${joinNames(picked.tie.between)}, resolve per your bylaws.`);
          }
        } else { /* majority */
          const needed = race.seats === 1 ? ballotsInRace / 2 : totalVotes / (2 * race.seats);
          const qualified = standings.filter((s) => s.votes > needed);
          const picked = pickWinnersWithTies(qualified, race.seats);
          winners = picked.winners.map((s) => s.name);
          if (picked.tie) {
            tieFlags.push(`Tie for ${seatLabel(picked.tie.firstSeat, picked.tie.lastSeat)} between ${joinNames(picked.tie.between)}, resolve per your bylaws.`);
          }
          /* A runoff covers only seats NO candidate reached a majority for.
           * A seat contested by a tie between majority holders is resolved
           * per bylaws (flagged above), not by a runoff. */
          const unfilled = Math.max(0, race.seats - qualified.length);
          const winnerIds = new Set(picked.winners.map((s) => s.id));
          const pool = standings.filter((s) => !winnerIds.has(s.id));
          if (unfilled > 0 && standings.length > 1 && pool.length > 0) {
            runoffRequired = true;
            runoffSeats = unfilled;
            /* Runoff field: top non-winning candidates, up to two per
             * unfilled seat (single seat therefore keeps its top-two rule),
             * plus everyone tied at that cutoff. */
            const cap = Math.min(2 * unfilled, pool.length);
            let take = cap;
            while (take < pool.length && pool[take].votes === pool[cap - 1].votes) take++;
            runoffBetween = pool.slice(0, take).map((s) => s.name);
            if (take > cap) {
              const tiedAtCutoff = pool.filter((s) => s.votes === pool[cap - 1].votes).map((s) => s.name);
              tieFlags.push(`Tie at the runoff cutoff between ${joinNames(tiedAtCutoff)}; all tied candidates are included in the runoff, resolve per your bylaws.`);
            }
          }
        }
        /*
         * SECRECY ARITHMETIC (task #4) — disclose, never pretend the seal
         * solves it. Sealing protects HOW ballots are stored, not what the
         * totals reveal. Two outcomes expose individuals no matter how well the
         * ballots were encrypted, so we record a plain-language flag on the
         * result itself (it therefore also lands in the one-year archive):
         *   - a race with very few ballots (each voter becomes guessable);
         *   - a unanimous single-choice race or question (every voter's choice
         *     is then effectively public).
         */
        const secrecyWarnings = [];
        if (ballotsInRace > 0 && ballotsInRace < SECRECY_MIN_BALLOTS) {
          secrecyWarnings.push(`Only ${ballotsInRace} ballot${ballotsInRace === 1 ? '' : 's'} ${ballotsInRace === 1 ? 'was' : 'were'} cast in this race. With so few voters, ballot secrecy is not mathematically guaranteed no matter how the ballots were sealed.`);
        }
        const singleChoice = race.seats === 1 || race.threshold === 'two_thirds';
        if (ballotsInRace > 0 && singleChoice && race.candidates.length > 1 && standings[0] && standings[0].votes === ballotsInRace) {
          secrecyWarnings.push('Unanimous result: every member who voted in this race chose the same option, so each voter\u2019s choice is effectively public regardless of the ballot seal.');
        }
        results.races.push({
          title: race.title, seats: race.seats, threshold: race.threshold,
          ballots_in_race: ballotsInRace, total_votes: totalVotes,
          standings, winners, runoff_required: runoffRequired, runoff_between: runoffBetween,
          runoff_seats: runoffSeats, tie_flags: tieFlags,
          secrecy_warnings: secrecyWarnings,
        });
      }

      db.prepare("UPDATE elections SET status='tallied', results_json=?, tallied_at=datetime('now') WHERE id=? AND local_id=?")
        .run(JSON.stringify(results), e.id, req.localId);
      audit(req.localId, req.session.user.username, 'tally.completed',
        `Election #${e.id} "${e.title}": ${ballots.length} ballots unsealed with ${e.key_threshold}-of-${e.key_shares_total} key shares and counted. Integrity ${results.integrity_ok ? 'OK' : 'ALERT — see log'}.`);

      /*
       * RETENTION SAFETY NET: persist the sealed records archive the moment
       * the tally lands, so the one-year record exists even if the committee
       * never clicks Export — and can be re-issued to the local later if it
       * loses its copy. Same contents as the manual export; encrypted at rest
       * under BACKUP_KEY when configured; never contains a key share or a
       * plaintext ballot. A failure here is audited but must NEVER undo or
       * block the tally itself — the results above are already committed.
       */
      try {
        const rec = writeSealedArchive(e.id, req.localId);
        audit(req.localId, req.session.user.username, 'election.archive_stored',
          `Election #${e.id}: sealed records archive stored automatically as ${rec.filename} (${rec.encrypted ? 'AES-256-GCM under BACKUP_KEY' : 'plaintext JSON — set BACKUP_KEY to encrypt archives at rest'}; ${rec.ballot_count} encrypted ballots; sha256 ${rec.sha256})`);
      } catch (archiveErr) {
        console.error('[archive] automatic records archive failed:', archiveErr.message);
        audit(req.localId, req.session.user.username, 'election.archive_store_failed',
          `Election #${e.id}: automatic records archive could NOT be stored (${String(archiveErr.message || 'unknown error').slice(0, 180)}). Export the archive manually from the election page and keep a copy off-site.`);
      }

      flash(req, 'ok', 'Tally complete. Publish the results to the membership and preserve all records for one year.');
      res.redirect(`/admin/elections/${e.id}`);
    } catch (err) { next(err); }
  });

  /* ---------------- records archive (1-year retention) ----------------
   * Manual export, unchanged in content: buildArchive() is shared with the
   * automatic tally-time sealed archive so the two can never diverge. */
  router.get('/elections/:id/archive', (req, res) => {
    const archive = buildArchive(req.params.id, req.localId);
    audit(req.localId, req.session.user.username, 'election.archive_exported', `Election #${archive.election.id}: records archive exported for retention`);
    res.setHeader('Content-Disposition', `attachment; filename="election-${archive.election.id}-records.json"`);
    res.json(archive);
  });

  /* ---------------- committee & observer accounts (this local only) ------ */
  router.get('/users', (req, res) => {
    const users = db.prepare('SELECT id, username, role, display_name, email, created_at FROM users WHERE local_id=? ORDER BY role, username').all(req.localId);
    res.render('admin/users', { title: 'Accounts', users, smtp: smtpConfigured() });
  });

  router.post('/users', (req, res) => {
    const { username, password, display_name, role } = req.body;
    if (!username || !password || password.length < 10) { flash(req, 'error', 'Observer accounts need a username and a password of at least 10 characters.'); return res.redirect('/admin/users'); }
    /* Recovery email is optional but, when given, must be deliverable as
     * written — same syntax gate as the member roster. */
    const email = (req.body.email || '').trim() || null;
    if (email) {
      const check = checkEmailSyntax(email);
      if (!check.ok) { flash(req, 'error', `Account not created. "${email}" does not look like a deliverable email address — ${check.reason}.`); return res.redirect('/admin/users'); }
    }
    const r = role === 'admin' ? 'admin' : 'observer';
    try {
      db.prepare('INSERT INTO users (local_id, username, password_hash, role, display_name, email) VALUES (?,?,?,?,?,?)')
        .run(req.localId, username.trim(), bcrypt.hashSync(password, 12), r, (display_name || username).trim(), email);
    } catch (err) {
      /* Usernames are unique across the whole platform (sign-in has no local
       * selector), so a collision with ANY local's account lands here. The
       * message deliberately does not say where the name is in use. */
      if (err && String(err.code || '').startsWith('SQLITE_CONSTRAINT')) {
        flash(req, 'error', `The username "${username.trim()}" is already in use on this platform. Pick a different one (e.g. add your local number).`);
        return res.redirect('/admin/users');
      }
      throw err;
    }
    audit(req.localId, req.session.user.username, 'users.created', `${r} account "${username.trim()}" created (${(display_name || username).trim()})${email ? ' with a recovery email on file' : ''}`);
    flash(req, 'ok', `${r === 'admin' ? 'Administrator' : 'Observer'} account created.`);
    res.redirect('/admin/users');
  });

  /* Set or clear an account's recovery email. Without one, the account
   * cannot use the emailed forgot-password flow — recovery then requires the
   * platform administrator to generate a one-time reset link. */
  router.post('/users/:id/email', (req, res) => {
    const u = tenant.getUser(req.localId, req.params.id);
    if (!u) return res.redirect('/admin/users');
    const email = (req.body.email || '').trim() || null;
    if (email) {
      const check = checkEmailSyntax(email);
      if (!check.ok) { flash(req, 'error', `Not saved. "${email}" does not look like a deliverable email address — ${check.reason}.`); return res.redirect('/admin/users'); }
    }
    db.prepare('UPDATE users SET email=? WHERE id=? AND local_id=?').run(email, u.id, req.localId);
    audit(req.localId, req.session.user.username, 'users.email_set',
      email ? `Recovery email set for account "${u.username}"` : `Recovery email removed from account "${u.username}"`);
    flash(req, 'ok', email
      ? `Recovery email saved for ${u.username}. Password-reset links can now be emailed to it.`
      : `Recovery email removed from ${u.username}. That account can no longer use the emailed reset flow.`);
    res.redirect('/admin/users');
  });

  return router;
};
