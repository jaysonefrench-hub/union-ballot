/**
 * routes/admin.js — Election-committee functions.
 *
 * Note what an administrator here can and cannot do:
 *   CAN:  manage the roster, configure votes, issue/void credentials,
 *         open/close voting, run the tally CEREMONY, export records.
 *   CANNOT: read any ballot. Ballots are sealed to the election public key;
 *         the private key exists only as Shamir shares held by keyholders
 *         (candidate representatives + a neutral). The tally requires K of N
 *         shares entered together, ideally with observers present.
 */
'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const { db, audit, verifyAuditChain, getReissueKey, purgeReissueMap } = require('../db');
const {
  generateElectionKeys, combineShares, decryptBallot,
  generateCredential, hashCredential, aesEncrypt, aesDecrypt, randomHex, secureShuffle,
  generateVerifyToken, hashVerifyToken,
} = require('../crypto');
const { smtpConfigured, sendCredentialEmail, sendVerificationEmail } = require('../mailer');

const BASE_URL = () => process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;

/* US state/territory codes for the election jurisdiction field. */
const US_JURISDICTIONS = [
  ['AL', 'Alabama'], ['AK', 'Alaska'], ['AZ', 'Arizona'], ['AR', 'Arkansas'], ['CA', 'California'],
  ['CO', 'Colorado'], ['CT', 'Connecticut'], ['DE', 'Delaware'], ['DC', 'District of Columbia'],
  ['FL', 'Florida'], ['GA', 'Georgia'], ['HI', 'Hawaii'], ['ID', 'Idaho'], ['IL', 'Illinois'],
  ['IN', 'Indiana'], ['IA', 'Iowa'], ['KS', 'Kansas'], ['KY', 'Kentucky'], ['LA', 'Louisiana'],
  ['ME', 'Maine'], ['MD', 'Maryland'], ['MA', 'Massachusetts'], ['MI', 'Michigan'], ['MN', 'Minnesota'],
  ['MS', 'Mississippi'], ['MO', 'Missouri'], ['MT', 'Montana'], ['NE', 'Nebraska'], ['NV', 'Nevada'],
  ['NH', 'New Hampshire'], ['NJ', 'New Jersey'], ['NM', 'New Mexico'], ['NY', 'New York'],
  ['NC', 'North Carolina'], ['ND', 'North Dakota'], ['OH', 'Ohio'], ['OK', 'Oklahoma'], ['OR', 'Oregon'],
  ['PA', 'Pennsylvania'], ['RI', 'Rhode Island'], ['SC', 'South Carolina'], ['SD', 'South Dakota'],
  ['TN', 'Tennessee'], ['TX', 'Texas'], ['UT', 'Utah'], ['VT', 'Vermont'], ['VA', 'Virginia'],
  ['WA', 'Washington'], ['WV', 'West Virginia'], ['WI', 'Wisconsin'], ['WY', 'Wyoming'],
  ['XX', 'Other / outside the United States'],
];
const JURISDICTION_CODES = new Set(US_JURISDICTIONS.map(([code]) => code));

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

function getElection(id) {
  const e = db.prepare('SELECT * FROM elections WHERE id=?').get(id);
  if (!e) { const err = new Error('no such election'); err.publicMessage = 'Election not found.'; throw err; }
  e.races = db.prepare('SELECT * FROM races WHERE election_id=? ORDER BY position, id').all(e.id);
  for (const r of e.races) r.candidates = db.prepare('SELECT * FROM candidates WHERE race_id=? ORDER BY position, id').all(r.id);
  return e;
}

module.exports = function adminRoutes({ flash }) {
  const router = express.Router();

  /* ---------------- dashboard ---------------- */
  router.get('/', (req, res) => {
    const elections = db.prepare('SELECT * FROM elections ORDER BY id DESC').all();
    for (const e of elections) {
      e.turnout = db.prepare('SELECT COUNT(*) AS n FROM turnout WHERE election_id=?').get(e.id).n;
      e.eligible = JSON.parse(e.eligibility_snapshot || '[]').length;
    }
    const memberCount = db.prepare('SELECT COUNT(*) AS n FROM members').get().n;
    res.render('admin/dashboard', { title: 'Election committee', elections, memberCount, smtp: smtpConfigured() });
  });

  /* ---------------- members ---------------- */
  router.get('/members', (req, res) => {
    const members = db.prepare('SELECT * FROM members ORDER BY name').all();
    res.render('admin/members', { title: 'Member roster', members, smtp: smtpConfigured() });
  });

  router.post('/members/import', async (req, res, next) => {
    try {
      const lines = String(req.body.roster || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      const ins = db.prepare('INSERT INTO members (name, email, member_number) VALUES (?,?,?)');
      const withEmail = []; // { id, name, email } — need verification before electronic delivery
      let added = 0;
      db.transaction(() => {
        for (const line of lines) {
          const [name, email, num] = line.split(',').map((s) => (s || '').trim());
          if (!name) continue;
          const info = ins.run(name, email || null, num || null);
          if (email) withEmail.push({ id: info.lastInsertRowid, name, email });
          added++;
        }
      })();
      audit(req.session.user.username, 'roster.import', `${added} members added to roster (${withEmail.length} with email, pending verification)`);

      /* Members with an email address start UNVERIFIED. If SMTP is configured,
       * send each a verification link now; otherwise they stay pending and the
       * committee sends links per member from the roster page. */
      if (smtpConfigured() && withEmail.length > 0) {
        let sent = 0; const failures = [];
        for (const m of withEmail) {
          const verifyUrl = beginEmailVerification(m.id);
          try {
            await sendVerificationEmail({ to: m.email, memberName: m.name, verifyUrl });
            sent++;
          } catch (err) { failures.push(`${m.name} <${m.email}>: ${err.message}`); }
        }
        audit(req.session.user.username, 'roster.verification_emails_sent', `${sent} email-verification link(s) sent after import, ${failures.length} failed`);
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
      const m = db.prepare('SELECT * FROM members WHERE id=?').get(req.params.id);
      if (!m) return res.redirect('/admin/members');
      const good = req.body.good_standing === '1' ? 1 : 0;
      const paper = req.body.needs_paper_ballot === '1' ? 1 : 0;
      const newEmail = (req.body.email || '').trim() || null;
      const emailChanged = (newEmail || '') !== (m.email || '');
      db.prepare('UPDATE members SET good_standing=?, needs_paper_ballot=?, email=? WHERE id=?')
        .run(good, paper, newEmail, m.id);
      /* A changed address is a NEW claim: any previous verification (and any
       * outstanding token) no longer proves anything about it. */
      if (emailChanged) {
        db.prepare('UPDATE members SET email_verified=0, email_verified_at=NULL, email_verify_token_hash=NULL, email_verify_sent_at=NULL WHERE id=?').run(m.id);
      }
      audit(req.session.user.username, 'roster.update', `Member #${m.id} (${m.name}): good_standing=${good}, paper=${paper}${emailChanged ? '; email changed — verification reset' : ''}`);
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
      const m = db.prepare('SELECT * FROM members WHERE id=?').get(req.params.id);
      if (!m) return res.redirect('/admin/members');
      if (!m.email) { flash(req, 'error', `${m.name} has no email address on the roster; they use the paper-ballot method.`); return res.redirect('/admin/members'); }
      if (m.email_verified) { flash(req, 'ok', `${m.name}'s email address is already verified.`); return res.redirect('/admin/members'); }

      const verifyUrl = beginEmailVerification(m.id);
      if (smtpConfigured()) {
        await sendVerificationEmail({ to: m.email, memberName: m.name, verifyUrl });
        audit(req.session.user.username, 'roster.verification_email_sent', `Verification link (re)sent to member #${m.id} (${m.name}); any previous link is now invalid`);
        flash(req, 'ok', `Verification link emailed to ${m.name} <${m.email}>. Any earlier link no longer works.`);
        res.redirect('/admin/members');
      } else {
        /* No SMTP: show the link exactly once for manual delivery (same
         * pattern as the one-time credential export). */
        audit(req.session.user.username, 'roster.verification_link_displayed', `One-time verification link displayed for member #${m.id} (${m.name}) for manual delivery; any previous link is now invalid`);
        res.render('admin/verify-link-once', { title: 'One-time verification link', m, verifyUrl });
      }
    } catch (err) { next(err); }
  });

  /* ---------------- create election + key ceremony ---------------- */
  router.get('/elections/new', (req, res) => {
    res.render('admin/election-new', { title: 'New vote', jurisdictions: US_JURISDICTIONS });
  });

  router.post('/elections/new', (req, res) => {
    const { title, kind, opens_at, closes_at, notice_sent_on } = req.body;
    const isTest = req.body.is_test === '1' ? 1 : 0;

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
      audit(req.session.user.username, 'election.create_blocked_perc',
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
        (title, kind, jurisdiction, perc_variance_ack, perc_variance_ref, iaff_legal_approval, is_test, status, notice_sent_on, opens_at, closes_at, public_key, key_shares_total, key_threshold, keyholders)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(title.trim(), kind, jurisdiction, percAck, percRef || null, approvalRef || null, isTest, 'draft', notice_sent_on || null, opens_at || null, closes_at || null,
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

    audit(req.session.user.username, 'election.created',
      `Election #${electionId} "${title.trim()}" (${kind}${isTest ? ', TEST' : ''}, jurisdiction ${jurisdiction}) created; ballot key split ${threshold}-of-${sharesTotal}; keyholders: ${keyholders.join('; ') || 'not recorded'}${approvalRef ? `; IAFF Legal Dept approval recorded: ${approvalRef}` : ''}${percAck ? `; committee recorded its claim of a current Florida PERC variance for electronic ratification${percRef ? ` (ref: ${percRef})` : ''} — not verified by this system` : ''}`);

    /* Shares are displayed exactly once and never stored. */
    res.render('admin/shares-once', {
      title: 'Key ceremony — distribute these shares now',
      electionId, shares: keys.shares, threshold, keyholders,
    });
  });

  /* ---------------- election detail ---------------- */
  router.get('/elections/:id', (req, res) => {
    const e = getElection(req.params.id);
    const credStats = db.prepare('SELECT COUNT(*) AS total, SUM(redeemed) AS used, SUM(voided) AS voided FROM credentials WHERE election_id=?').get(e.id);
    const ballotCount = db.prepare('SELECT COUNT(*) AS n FROM ballots WHERE election_id=?').get(e.id).n;
    const turnout = db.prepare(`SELECT m.name, t.voted_on, t.method FROM turnout t JOIN members m ON m.id=t.member_id WHERE t.election_id=? ORDER BY m.name`).all(e.id);
    const eligible = JSON.parse(e.eligibility_snapshot || '[]');
    const eligibleMembers = eligible.map((s) => {
      const m = db.prepare('SELECT id, name FROM members WHERE id=?').get(s.member_id);
      return { member_id: s.member_id, name: m ? m.name : `member #${s.member_id}`, method: s.method };
    });
    const paperMembers = db.prepare("SELECT * FROM members WHERE good_standing=1 AND (needs_paper_ballot=1 OR email IS NULL OR email='')").all();
    /* Members headed for the electronic path whose email is still unverified:
     * issuance is blocked while any of these remain. */
    const unverifiedMembers = db.prepare("SELECT * FROM members WHERE good_standing=1 AND needs_paper_ballot=0 AND email IS NOT NULL AND email!='' AND email_verified=0 ORDER BY name").all();
    /* Reissue-map state: is the encrypted member<->credential map still present,
     * or has it already been purged? Drives the post-close purge control. */
    const rm = db.prepare("SELECT COUNT(*) AS total, SUM(CASE WHEN member_ref<>'' THEN 1 ELSE 0 END) AS present FROM credentials WHERE election_id=?").get(e.id);
    const reissueMapPresent = (rm.present || 0) > 0;
    const reissueMapPurged = rm.total > 0 && (rm.present || 0) === 0;
    res.render('admin/election-detail', {
      title: e.title, e, credStats, ballotCount, turnout, eligibleCount: eligible.length, eligibleMembers,
      paperMembers, unverifiedMembers, smtp: smtpConfigured(), reissueMapPresent, reissueMapPurged,
      results: e.results_json ? JSON.parse(e.results_json) : null,
    });
  });

  /* ---------------- issue credentials ---------------- */
  router.post('/elections/:id/issue-credentials', async (req, res, next) => {
    try {
      const e = getElection(req.params.id);
      if (e.status !== 'draft') { flash(req, 'error', 'Credentials were already issued for this vote.'); return res.redirect(`/admin/elections/${e.id}`); }
      if (percRatificationBlocked({ jurisdiction: e.jurisdiction, kind: e.kind, isTest: e.is_test, varianceAck: e.perc_variance_ack })) {
        audit(req.session.user.username, 'election.credential_issue_blocked_perc',
          `Election #${e.id} "${e.title}": credential issuance blocked — binding Florida electronic contract ratification without a recorded PERC variance acknowledgment (FAC 60CC-4.002)`);
        flash(req, 'error', PERC_BLOCK_MESSAGE);
        return res.redirect(`/admin/elections/${e.id}`);
      }

      /*
       * EMAIL VERIFICATION GATE: electronic credentials go only to VERIFIED
       * addresses. Members on the paper path (flagged, or no email) are
       * unaffected — no verification is required to receive a paper ballot.
       * If anyone is headed for the electronic path with an unverified email,
       * refuse to issue rather than silently dropping them from both paths.
       */
      const electronic = db.prepare("SELECT * FROM members WHERE good_standing=1 AND needs_paper_ballot=0 AND email IS NOT NULL AND email != '' AND email_verified=1 ORDER BY name").all();
      const paper = db.prepare("SELECT * FROM members WHERE good_standing=1 AND (needs_paper_ballot=1 OR email IS NULL OR email='') ORDER BY name").all();
      const unverified = db.prepare("SELECT * FROM members WHERE good_standing=1 AND needs_paper_ballot=0 AND email IS NOT NULL AND email!='' AND email_verified=0 ORDER BY name").all();
      if (unverified.length > 0) {
        audit(req.session.user.username, 'election.credential_issue_blocked_unverified',
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
        db.prepare("UPDATE elections SET status='credentials_issued', eligibility_snapshot=? WHERE id=?")
          .run(JSON.stringify(snapshot), e.id);
      })();

      audit(req.session.user.username, 'election.credentials_issued',
        `Election #${e.id}: ${issued.length} electronic credentials generated (random, hashed at rest); ${paper.length} member(s) flagged for the alternative paper-ballot method`);

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
        audit(req.session.user.username, 'election.credentials_emailed', `Election #${e.id}: ${sent} credential emails sent, ${failures.length} failed`);
        res.render('admin/credentials-sent', { title: 'Credentials emailed', e, sent, failures, paper });
      } else {
        /* One-time export for mail-merge; shown once, never retrievable again. */
        audit(req.session.user.username, 'election.credentials_exported', `Election #${e.id}: one-time credential export displayed for mail-merge delivery`);
        res.render('admin/credentials-export', { title: 'One-time credential export', e, issued, paper, voteUrl });
      }
    } catch (err) { next(err); }
  });

  /* ---------------- reissue a lost credential ---------------- */
  router.post('/elections/:id/reissue', async (req, res, next) => {
    try {
      const e = getElection(req.params.id);
      const memberId = Number(req.body.member_id);
      const member = db.prepare('SELECT * FROM members WHERE id=?').get(memberId);
      if (!member || !['credentials_issued', 'open'].includes(e.status)) { flash(req, 'error', 'Reissue is only possible after credentials are issued and before the vote closes.'); return res.redirect(`/admin/elections/${e.id}`); }

      const reissueKey = getReissueKey();
      const rows = db.prepare('SELECT * FROM credentials WHERE election_id=? AND voided=0').all(e.id);
      const own = rows.find((c) => { try { return Number(aesDecrypt(c.member_ref, reissueKey)) === memberId; } catch { return false; } });
      if (own && own.redeemed) { flash(req, 'error', `${member.name}'s credential was already used to cast a ballot; it cannot be reissued. If the member disputes this, treat it as a security incident.`); audit(req.session.user.username, 'election.reissue_blocked', `Election #${e.id}: reissue for member #${memberId} blocked — credential already redeemed`); return res.redirect(`/admin/elections/${e.id}`); }

      const credential = generateCredential();
      const salt = randomHex(16);
      db.transaction(() => {
        if (own) db.prepare('UPDATE credentials SET voided=1 WHERE id=?').run(own.id);
        db.prepare('INSERT INTO credentials (election_id, code_hash, salt, member_ref) VALUES (?,?,?,?)')
          .run(e.id, hashCredential(credential, salt), salt, aesEncrypt(String(memberId), reissueKey));
      })();
      audit(req.session.user.username, 'election.credential_reissued', `Election #${e.id}: credential voided and reissued for one member (old credential invalidated)`);

      const voteUrl = (process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`) + '/';
      /* Email delivery only to a still-verified address (it may have been
       * changed since issuance); otherwise fall back to the one-time display. */
      if (smtpConfigured() && member.email && member.email_verified) {
        await sendCredentialEmail({ to: member.email, memberName: member.name, electionTitle: e.title, credential, voteUrl, closesAt: e.closes_at });
        flash(req, 'ok', `A replacement credential was emailed to ${member.name}. The previous credential no longer works.`);
        res.redirect(`/admin/elections/${e.id}`);
      } else {
        res.render('admin/credentials-export', { title: 'Replacement credential (shown once)', e, issued: [{ member, credential }], paper: [], voteUrl });
      }
    } catch (err) { next(err); }
  });

  /* ---------------- open / close ---------------- */
  router.post('/elections/:id/open', (req, res) => {
    const e = getElection(req.params.id);
    if (e.status !== 'credentials_issued') { flash(req, 'error', 'Issue credentials before opening the vote.'); return res.redirect(`/admin/elections/${e.id}`); }
    /* Defense in depth: the Florida PERC ratification gate also holds at open,
     * covering elections created before this gate existed (or edited rows). */
    if (percRatificationBlocked({ jurisdiction: e.jurisdiction, kind: e.kind, isTest: e.is_test, varianceAck: e.perc_variance_ack })) {
      audit(req.session.user.username, 'election.open_blocked_perc',
        `Election #${e.id} "${e.title}": opening blocked — binding Florida electronic contract ratification without a recorded PERC variance acknowledgment (FAC 60CC-4.002)`);
      flash(req, 'error', PERC_BLOCK_MESSAGE);
      return res.redirect(`/admin/elections/${e.id}`);
    }
    db.prepare("UPDATE elections SET status='open' WHERE id=?").run(e.id);
    audit(req.session.user.username, 'election.opened', `Election #${e.id} "${e.title}" opened for voting`);
    flash(req, 'ok', 'Voting is open.');
    res.redirect(`/admin/elections/${e.id}`);
  });

  router.post('/elections/:id/close', (req, res) => {
    const e = getElection(req.params.id);
    if (e.status !== 'open') { flash(req, 'error', 'Only an open vote can be closed.'); return res.redirect(`/admin/elections/${e.id}`); }
    db.prepare("UPDATE elections SET status='closed' WHERE id=?").run(e.id);
    audit(req.session.user.username, 'election.closed', `Election #${e.id} "${e.title}" closed to voting`);
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
      const e = getElection(req.params.id);
      if (!['closed', 'tallied'].includes(e.status)) {
        flash(req, 'error', 'Close voting before purging the reissue map.');
        return res.redirect(`/admin/elections/${e.id}`);
      }
      const cleared = purgeReissueMap(e.id);
      audit(req.session.user.username, 'election.reissue_map_purged',
        `Election #${e.id} "${e.title}": member<->credential reissue map destroyed after close (${cleared} credential record(s) cleared). Hashed credentials, turnout, sealed ballots, and audit log retained.`);
      flash(req, 'ok', cleared > 0
        ? `Reissue map destroyed — ${cleared} record(s) cleared. The stored name-to-credential link no longer exists for this election.`
        : 'The reissue map was already empty for this election; nothing to purge.');
      res.redirect(`/admin/elections/${e.id}`);
    } catch (err) {
      /* purgeReissueMap throws with a publicMessage if voting is still open. */
      if (err && err.publicMessage) { flash(req, 'error', err.publicMessage); return res.redirect(`/admin/elections/${req.params.id}`); }
      next(err);
    }
  });

  /* ---------------- record a paper ballot received ---------------- */
  router.post('/elections/:id/paper-received', (req, res) => {
    const e = getElection(req.params.id);
    const memberId = Number(req.body.member_id);
    if (!['open', 'closed'].includes(e.status)) { flash(req, 'error', 'Paper ballots can be recorded while the vote is open or closed (before tally).'); return res.redirect(`/admin/elections/${e.id}`); }
    db.prepare('INSERT OR IGNORE INTO turnout (election_id, member_id, voted_on, method) VALUES (?,?,date(\'now\'),\'paper\')').run(e.id, memberId);
    audit(req.session.user.username, 'election.paper_ballot_received', `Election #${e.id}: a sealed paper ballot was logged as received (member marked as voted)`);
    flash(req, 'ok', 'Paper ballot receipt recorded. Count paper ballots with observers present and add them to the electronic results.');
    res.redirect(`/admin/elections/${e.id}`);
  });

  /* ---------------- tally ceremony ---------------- */
  router.get('/elections/:id/tally', (req, res) => {
    const e = getElection(req.params.id);
    if (e.status !== 'closed') { flash(req, 'error', 'Close the vote before tallying.'); return res.redirect(`/admin/elections/${e.id}`); }
    res.render('admin/tally', { title: 'Tally ceremony', e });
  });

  router.post('/elections/:id/tally', (req, res, next) => {
    try {
      const e = getElection(req.params.id);
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
        audit(req.session.user.username, 'tally.key_reconstruction_failed', `Election #${e.id}: key share combination failed — ${err.message}`);
        flash(req, 'error', err.message);
        return res.redirect(`/admin/elections/${e.id}/tally`);
      }

      const rows = db.prepare('SELECT payload FROM ballots WHERE election_id=?').all(e.id);
      /* Integrity check: sealed ballots must equal redeemed credentials. */
      const redeemed = db.prepare('SELECT COUNT(*) AS n FROM credentials WHERE election_id=? AND redeemed=1').get(e.id).n;
      if (rows.length !== redeemed) {
        audit(req.session.user.username, 'tally.INTEGRITY_ALERT', `Election #${e.id}: ballot count (${rows.length}) does not match redeemed credentials (${redeemed}) — investigate before certifying`);
      }

      /* Shuffle before decrypting so even the ceremony reveals no order. */
      const shuffled = secureShuffle(rows);
      const ballots = [];
      let failed = 0;
      for (const row of shuffled) {
        try { ballots.push(decryptBallot(row.payload, privateKey)); } catch { failed++; }
      }
      if (failed > 0 && ballots.length === 0) {
        audit(req.session.user.username, 'tally.decrypt_failed', `Election #${e.id}: ballots failed to decrypt — wrong shares or tampering`);
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
         *    (the standard union election-manual method).
         *  - two_thirds (bylaw amendments): top option needs >= 2/3 of
         *    ballots cast in the question.
         *  - plurality: top N win.
         */
        let winners = []; let runoffRequired = false; let runoffBetween = [];
        if (race.threshold === 'plurality') {
          winners = standings.slice(0, race.seats).filter((s) => s.votes > 0).map((s) => s.name);
        } else if (race.threshold === 'two_thirds') {
          const top = standings[0];
          if (top && ballotsInRace > 0 && top.votes >= (2 / 3) * ballotsInRace) winners = [top.name];
        } else { /* majority */
          const needed = race.seats === 1 ? ballotsInRace / 2 : totalVotes / (2 * race.seats);
          winners = standings.filter((s) => s.votes > needed).slice(0, race.seats).map((s) => s.name);
          if (winners.length < race.seats && standings.length > 1) {
            runoffRequired = true;
            runoffBetween = standings.slice(0, 2).map((s) => s.name);
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
          secrecy_warnings: secrecyWarnings,
        });
      }

      db.prepare("UPDATE elections SET status='tallied', results_json=?, tallied_at=datetime('now') WHERE id=?")
        .run(JSON.stringify(results), e.id);
      audit(req.session.user.username, 'tally.completed',
        `Election #${e.id} "${e.title}": ${ballots.length} ballots unsealed with ${e.key_threshold}-of-${e.key_shares_total} key shares and counted. Integrity ${results.integrity_ok ? 'OK' : 'ALERT — see log'}.`);

      flash(req, 'ok', 'Tally complete. Publish the results to the membership and preserve all records for one year.');
      res.redirect(`/admin/elections/${e.id}`);
    } catch (err) { next(err); }
  });

  /* ---------------- records archive (1-year retention) ---------------- */
  router.get('/elections/:id/archive', (req, res) => {
    const e = getElection(req.params.id);
    const archive = {
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
    audit(req.session.user.username, 'election.archive_exported', `Election #${e.id}: records archive exported for retention`);
    res.setHeader('Content-Disposition', `attachment; filename="election-${e.id}-records.json"`);
    res.json(archive);
  });

  /* ---------------- observer accounts ---------------- */
  router.get('/users', (req, res) => {
    const users = db.prepare('SELECT id, username, role, display_name, created_at FROM users ORDER BY role, username').all();
    res.render('admin/users', { title: 'Accounts', users });
  });

  router.post('/users', (req, res) => {
    const { username, password, display_name, role } = req.body;
    if (!username || !password || password.length < 10) { flash(req, 'error', 'Observer accounts need a username and a password of at least 10 characters.'); return res.redirect('/admin/users'); }
    const r = role === 'admin' ? 'admin' : 'observer';
    db.prepare('INSERT INTO users (username, password_hash, role, display_name) VALUES (?,?,?,?)')
      .run(username.trim(), bcrypt.hashSync(password, 12), r, (display_name || username).trim());
    audit(req.session.user.username, 'users.created', `${r} account "${username.trim()}" created (${(display_name || username).trim()})`);
    flash(req, 'ok', `${r === 'admin' ? 'Administrator' : 'Observer'} account created.`);
    res.redirect('/admin/users');
  });

  return router;
};
