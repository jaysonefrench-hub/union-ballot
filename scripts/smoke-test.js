/**
 * scripts/smoke-test.js — Full end-to-end election against the live server.
 * Verifies: setup → roster → create (with IAFF approval gate) → key ceremony →
 * credentials → open → 6 ballots cast → close → tally with 3-of-5 shares →
 * majority/runoff math → anonymity properties of stored data → roster-import
 * email-syntax gate (report of rejected rows) → member-edit email gate →
 * automatic sealed archive at tally → platform-owner page (key gate, counts
 * only, archive download) → committee password reset (hash-only tokens).
 */
'use strict';
const crypto = require('crypto');
process.env.DATA_DIR = require('path').join(__dirname, '..', 'data-test');
process.env.PORT = '3999';
/* The test creates a binding (non-test) election, and getReissueKey() refuses
 * to auto-generate a key once one exists — so supply a throwaway key, exactly
 * as a real deployment would via the environment. */
process.env.REISSUE_KEY = process.env.REISSUE_KEY || crypto.randomBytes(32).toString('hex');
/* Exercise the platform-owner page and encrypted-at-rest archives. */
const PLATFORM_KEY = 'platform-owner-test-key-0123456789';
process.env.PLATFORM_OWNER_KEY = PLATFORM_KEY;
const BACKUP_KEY_HEX = crypto.randomBytes(32).toString('hex');
process.env.BACKUP_KEY = BACKUP_KEY_HEX;
const fs = require('fs');
const path = require('path');
fs.rmSync(process.env.DATA_DIR, { recursive: true, force: true });

const app = require('../server');
const { db } = require('../src/db');
const assert = require('assert');

const BASE = 'http://localhost:3999';
let cookie = '';

async function req(method, path, body, useCookie = true) {
  const headers = {};
  if (useCookie && cookie) headers.Cookie = cookie;
  let payload;
  if (body) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(body)) {
      if (Array.isArray(v)) v.forEach((x) => p.append(k, x)); else p.append(k, v);
    }
    payload = p.toString();
  }
  const r = await fetch(BASE + path, { method, headers, body: payload, redirect: 'manual' });
  const setc = r.headers.get('set-cookie');
  if (setc && useCookie) cookie = setc.split(';')[0]; // never let anonymous voter sessions clobber the admin session
  return { status: r.status, text: await r.text(), location: r.headers.get('location') };
}

/* Cookie-less request with custom headers (for X-Platform-Key testing). */
async function reqHeaders(method, path, headers) {
  const r = await fetch(BASE + path, { method, headers, redirect: 'manual' });
  return { status: r.status, text: await r.text(), location: r.headers.get('location') };
}

/* Cookie-less binary download with custom headers. */
async function reqBinary(path, headers) {
  const r = await fetch(BASE + path, { headers, redirect: 'manual' });
  return { status: r.status, buf: Buffer.from(await r.arrayBuffer()), location: r.headers.get('location') };
}

/* Open a sealed .ubk buffer (backup/archive format: MAGIC | iv | tag | ct). */
function decryptSealed(buf, keyHex) {
  const MAGIC = Buffer.from('UNIONBALLOT1\n', 'utf8');
  assert.ok(buf.subarray(0, MAGIC.length).equals(MAGIC), 'sealed file carries the UNIONBALLOT1 header');
  let off = MAGIC.length;
  const iv = buf.subarray(off, off + 12); off += 12;
  const tag = buf.subarray(off, off + 16); off += 16;
  const d = crypto.createDecipheriv('aes-256-gcm', Buffer.from(keyHex, 'hex'), iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(buf.subarray(off)), d.final()]);
}

(async () => {
  const server = app.listen(3999);
  try {
    /* 1. First-run setup + login */
    await req('POST', '/setup', { username: 'chair', password: 'committee-pass-1', display_name: 'Committee Chair' });
    await req('POST', '/login', { username: 'chair', password: 'committee-pass-1' });

    /* 2. Roster: 6 electronic voters + 1 paper member */
    const roster = ['Alice A, a@x.test, 1', 'Bob B, b@x.test, 2', 'Cara C, c@x.test, 3',
      'Dan D, d@x.test, 4', 'Eve E, e@x.test, 5', 'Fay F, f@x.test, 6', 'Gus G (no email), , 7'].join('\n');
    await req('POST', '/admin/members/import', { roster });
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM members').get().n, 7, 'roster imported');

    /* 2b. Email verification: everyone with an email starts UNVERIFIED */
    assert.strictEqual(db.prepare("SELECT COUNT(*) n FROM members WHERE email IS NOT NULL AND email_verified=1").get().n, 0,
      'imported members start with unverified emails');

    /* 3. IAFF approval gate: officer election WITHOUT approval must be rejected */
    let r = await req('POST', '/admin/elections/new', {
      title: 'Should Fail', kind: 'officer_election', jurisdiction: 'OH',
      race_title: 'President', race_seats: '1', race_threshold: 'majority', race_candidates: 'X\nY',
      key_shares_total: '5', key_threshold: '3', keyholders: '',
    });
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM elections').get().n, 0, 'approval gate blocks unapproved officer election');

    /* 3b. Jurisdiction is required */
    r = await req('POST', '/admin/elections/new', {
      title: 'No Jurisdiction', kind: 'other',
      race_title: 'Q', race_seats: '1', race_threshold: 'majority', race_candidates: 'Yes\nNo',
      key_shares_total: '5', key_threshold: '3', keyholders: '',
    });
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM elections').get().n, 0, 'missing jurisdiction blocks creation');

    /* 4. Create officer election WITH recorded approval; capture key shares */
    r = await req('POST', '/admin/elections/new', {
      title: '2026 Officer Election', kind: 'officer_election', jurisdiction: 'OH',
      iaff_legal_approval: 'IAFF Legal Dept letter 2026-06-01 ref L-1234',
      notice_sent_on: '2026-06-20',
      race_title: ['President', 'Shall dues increase $5/mo?'],
      race_seats: ['1', '1'],
      race_threshold: ['majority', 'two_thirds'],
      race_candidates: ['Smith\nJones\nRivera', 'Yes\nNo'],
      key_shares_total: '5', key_threshold: '3',
      keyholders: 'Rep Smith\nRep Jones\nRep Rivera\nNeutral 1\nNeutral 2',
    });
    const shares = [...r.text.matchAll(/SHARE-\d+-[0-9a-f]+/g)].map((m) => m[0]);
    assert.strictEqual(shares.length, 5, 'five key shares displayed once');
    const eid = db.prepare('SELECT id FROM elections ORDER BY id DESC LIMIT 1').get().id;

    /* 4b. Credential issuance must be BLOCKED while electronic-path emails are unverified */
    r = await req('POST', `/admin/elections/${eid}/issue-credentials`, {});
    assert.strictEqual(db.prepare("SELECT status FROM elections WHERE id=?").get(eid).status, 'draft',
      'issuance blocked: election still draft while emails unverified');
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM credentials WHERE election_id=?').get(eid).n, 0,
      'issuance blocked: no credentials created for unverified members');

    /* 4c. Verify each electronic member via their one-time link (no SMTP →
     * the resend route displays the link once; capture and follow it). */
    const emembers = db.prepare("SELECT * FROM members WHERE email IS NOT NULL ORDER BY id").all();
    assert.strictEqual(emembers.length, 6);
    let firstToken = null;
    for (const m of emembers) {
      const page = await req('POST', `/admin/members/${m.id}/send-verification`, {});
      const match = page.text.match(/\/verify-email\?token=([0-9a-f]{32})/);
      assert.ok(match, `one-time verification link displayed for ${m.name}`);
      if (!firstToken) firstToken = match[1];
      /* token stored only as a hash, never in plaintext */
      assert.ok(!db.serialize().toString('latin1').includes(match[1]), 'verification token plaintext never stored');
      const v = await req('GET', `/verify-email?token=${match[1]}`, null, false);
      assert.ok(v.text.includes('confirmed'), `${m.name} email verified via link`);
    }
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM members WHERE email_verified=1').get().n, 6, 'all six emails verified');
    /* tokens are single-use and bad tokens are rejected */
    let v = await req('GET', `/verify-email?token=${firstToken}`, null, false);
    assert.strictEqual(v.status, 400, 'used verification token rejected');
    v = await req('GET', '/verify-email?token=deadbeefdeadbeefdeadbeefdeadbeef', null, false);
    assert.strictEqual(v.status, 400, 'unknown verification token rejected');
    /* changing a member's email resets verification */
    const alice = emembers[0];
    await req('POST', `/admin/members/${alice.id}/update`, { email: 'new-a@x.test', good_standing: '1', needs_paper_ballot: '0' });
    assert.strictEqual(db.prepare('SELECT email_verified FROM members WHERE id=?').get(alice.id).email_verified, 0, 'email change resets verification');
    /* restore and re-verify so issuance can proceed */
    await req('POST', `/admin/members/${alice.id}/update`, { email: 'a@x.test', good_standing: '1', needs_paper_ballot: '0' });
    const relink = await req('POST', `/admin/members/${alice.id}/send-verification`, {});
    await req('GET', relink.text.match(/\/verify-email\?token=[0-9a-f]{32}/)[0], null, false);

    /* 5. Issue credentials (no SMTP → one-time export) and capture them */
    r = await req('POST', `/admin/elections/${eid}/issue-credentials`, {});
    const creds = [...r.text.matchAll(/[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}/g)].map((m) => m[0]);
    assert.strictEqual(creds.length, 6, 'six electronic credentials issued (paper member excluded)');
    assert.ok(r.text.includes('Gus G'), 'paper-ballot member listed for alternative method');
    /* plaintext credentials must NOT be in the database */
    const dbdump = db.serialize().toString('latin1');
    for (const c of creds) assert.ok(!dbdump.includes(c.replace(/-/g, '')) && !dbdump.includes(c), 'credential plaintext never stored');

    /* 6. Open voting */
    await req('POST', `/admin/elections/${eid}/open`, {});

    /* 7. Cast 6 ballots as anonymous voters (no session cookie) */
    const races = db.prepare('SELECT * FROM races WHERE election_id=? ORDER BY position').all(eid);
    const [pres, dues] = races;
    const cand = db.prepare('SELECT * FROM candidates WHERE race_id=? ORDER BY position');
    const [smith, jones, rivera] = cand.all(pres.id);
    const [yes, no] = cand.all(dues.id);

    // votes: Smith 4, Jones 1, Rivera 1  -> Smith majority (4/6)
    // dues: Yes 4, No 2 -> 66.7% >= 2/3 -> adopted
    const plan = [
      [smith.id, yes.id], [smith.id, yes.id], [smith.id, yes.id],
      [smith.id, no.id], [jones.id, yes.id], [rivera.id, no.id],
    ];
    for (let i = 0; i < 6; i++) {
      const body = { credential: creds[i] };
      body['race_' + pres.id] = String(plan[i][0]);
      body['race_' + dues.id] = String(plan[i][1]);
      const rr = await req('POST', '/vote/cast', body, false);
      assert.ok(rr.text.includes('Your ballot was cast'), `ballot ${i + 1} cast`);
      assert.ok(!rr.text.includes('Smith') && !rr.text.includes('Yes —'), 'confirmation never echoes choices');
    }

    /* 8. Double-vote must be rejected */
    const dbl = await req('POST', '/vote', { credential: creds[0] }, false);
    assert.strictEqual(dbl.status, 302, 'reused credential bounced back');

    /* 9. Anonymity properties of stored data */
    const brows = db.prepare('SELECT * FROM ballots').all();
    assert.strictEqual(brows.length, 6, 'six sealed ballots');
    for (const b of brows) {
      assert.deepStrictEqual(Object.keys(b).sort(), ['election_id', 'id', 'payload'], 'ballot rows carry nothing but id/election/ciphertext');
      assert.ok(!b.payload.includes('Smith'), 'ballot content encrypted');
    }
    const credRows = db.prepare('SELECT * FROM credentials').all();
    assert.ok(credRows.every((c) => !('ballot_id' in c)), 'credentials never reference ballots');
    assert.ok(credRows.filter((c) => c.redeemed).every((c) => /^\d{4}-\d{2}-\d{2}$/.test(c.redeemed_on)), 'redemption recorded as date only, no time');

    /* 10. Tally must fail with too few shares, succeed with 3 of 5 */
    await req('POST', `/admin/elections/${eid}/close`, {});
    let t = await req('POST', `/admin/elections/${eid}/tally`, { share: [shares[0], shares[2]] });
    assert.ok(t.location && t.location.includes('/tally'), 'two shares rejected (threshold is 3)');
    t = await req('POST', `/admin/elections/${eid}/tally`, { share: [shares[0], shares[2], shares[4]] });

    const results = JSON.parse(db.prepare('SELECT results_json FROM elections WHERE id=?').get(eid).results_json);
    assert.strictEqual(results.ballots_cast, 6);
    assert.ok(results.integrity_ok, 'ballots == redeemed credentials');
    const presR = results.races[0];
    assert.deepStrictEqual(presR.winners, ['Smith'], 'Smith wins with majority 4/6');
    assert.strictEqual(presR.runoff_required, false);
    const duesR = results.races[1];
    assert.deepStrictEqual(duesR.winners, ['Yes'], 'dues question adopted at exactly 2/3');

    /* 11. Audit chain intact and never mentions voters next to ballots */
    const { verifyAuditChain } = require('../src/db');
    const chain = verifyAuditChain();
    assert.ok(chain.ok, 'audit chain verifies');
    const castLogs = db.prepare("SELECT detail FROM audit_log WHERE event='vote.ballot_cast'").all();
    assert.strictEqual(castLogs.length, 6);
    assert.ok(castLogs.every((l) => !/Alice|Bob|Cara|Dan|Eve|Fay/.test(l.detail)), 'cast events are anonymous');

    /* 12. Records archive exports */
    const arch = await req('GET', `/admin/elections/${eid}/archive`);
    const archive = JSON.parse(arch.text);
    assert.strictEqual(archive.encrypted_ballots.length, 6, 'archive preserves encrypted ballots');
    assert.ok(archive.audit_chain_verification.ok);

    /* 12b. AUTOMATIC SEALED ARCHIVE AT TALLY — written without anyone asking,
     * encrypted at rest under BACKUP_KEY, listed by metadata only. */
    const archRow = db.prepare('SELECT * FROM archives WHERE election_id=?').get(eid);
    assert.ok(archRow, 'tally automatically stored a sealed records archive');
    assert.strictEqual(archRow.ballot_count, 6, 'archive metadata records the encrypted-ballot count');
    assert.strictEqual(archRow.encrypted, 1, 'archive is encrypted at rest (BACKUP_KEY set)');
    assert.strictEqual(archRow.election_title, '2026 Officer Election');
    const archPath = path.join(process.env.DATA_DIR, 'archives', archRow.filename);
    assert.ok(fs.existsSync(archPath), 'archive file exists under DATA_DIR/archives');
    const fileBuf = fs.readFileSync(archPath);
    assert.strictEqual(crypto.createHash('sha256').update(fileBuf).digest('hex'), archRow.sha256, 'stored sha256 matches the file');
    const autoArchive = JSON.parse(decryptSealed(fileBuf, BACKUP_KEY_HEX).toString('utf8'));
    assert.strictEqual(autoArchive.election.id, eid, 'sealed archive holds the tallied election');
    assert.strictEqual(autoArchive.encrypted_ballots.length, 6, 'sealed archive preserves the encrypted ballots');
    assert.deepStrictEqual(autoArchive.results.races[0].winners, ['Smith'], 'sealed archive preserves the results');
    const archivePlain = decryptSealed(fileBuf, BACKUP_KEY_HEX).toString('latin1');
    for (const s of shares) assert.ok(!archivePlain.includes(s) && !archivePlain.includes(s.split('-')[2]), 'sealed archive contains no key share');
    for (const c of creds) assert.ok(!archivePlain.includes(c.replace(/-/g, '')) && !archivePlain.includes(c), 'sealed archive contains no credential plaintext');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.archive_stored'").get().n >= 1, 'automatic archive is audited');

    /* 13. FLORIDA PERC HARD STOP — contract ratification only */
    const baseVote = {
      race_title: 'Shall the tentative agreement be ratified?', race_seats: '1',
      race_threshold: 'majority', race_candidates: 'Yes — ratify\nNo — reject',
      key_shares_total: '5', key_threshold: '3', keyholders: '',
    };
    const electionCount = () => db.prepare('SELECT COUNT(*) n FROM elections').get().n;
    let n0 = electionCount();

    /* 13a. Binding FL ratification WITHOUT a variance ack → blocked */
    await req('POST', '/admin/elections/new', { ...baseVote, title: 'FL TA Ratification (no variance)', kind: 'contract_ratification', jurisdiction: 'FL' });
    assert.strictEqual(electionCount(), n0, 'binding FL electronic ratification blocked without PERC variance ack');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.create_blocked_perc'").get().n >= 1, 'PERC block is audited');

    /* 13b. Binding FL ratification WITH the recorded variance ack → allowed, flag stored */
    await req('POST', '/admin/elections/new', { ...baseVote, title: 'FL TA Ratification (variance claimed)', kind: 'contract_ratification', jurisdiction: 'FL', perc_variance_ack: '1', perc_variance_ref: 'PERC variance order 2026-03-15' });
    assert.strictEqual(electionCount(), n0 + 1, 'FL ratification allowed when committee records a PERC variance');
    const flVar = db.prepare('SELECT * FROM elections ORDER BY id DESC LIMIT 1').get();
    assert.strictEqual(flVar.perc_variance_ack, 1, 'variance acknowledgment stored on the election');
    assert.strictEqual(flVar.perc_variance_ref, 'PERC variance order 2026-03-15', 'variance reference stored');

    /* 13c. FL TEST-election ratification → allowed without a variance */
    await req('POST', '/admin/elections/new', { ...baseVote, title: 'FL TA Ratification (test run)', kind: 'contract_ratification', jurisdiction: 'FL', is_test: '1' });
    assert.strictEqual(electionCount(), n0 + 2, 'FL ratification test election allowed without variance');

    /* 13d. FL NON-ratification votes are NOT blocked (bylaws, officer election) */
    await req('POST', '/admin/elections/new', { ...baseVote, title: 'FL Bylaw Amendment', kind: 'bylaw_amendment', jurisdiction: 'FL' });
    assert.strictEqual(electionCount(), n0 + 3, 'FL bylaw amendment not blocked');
    await req('POST', '/admin/elections/new', { ...baseVote, title: 'FL Officer Election', kind: 'officer_election', jurisdiction: 'FL', iaff_legal_approval: 'IAFF Legal Dept letter 2026-06-01' });
    assert.strictEqual(electionCount(), n0 + 4, 'FL officer election not blocked by PERC gate');

    /* 13e. Non-FL ratification → not blocked */
    await req('POST', '/admin/elections/new', { ...baseVote, title: 'OH TA Ratification', kind: 'contract_ratification', jurisdiction: 'OH' });
    assert.strictEqual(electionCount(), n0 + 5, 'non-Florida ratification not blocked');

    /* 14. ROSTER IMPORT EMAIL-SYNTAX VALIDATION
     * Bad addresses must be caught at import — reported row-by-row with a
     * reason, never imported (they would sit as "Pending" forever), and never
     * failing the whole upload: valid rows still land on the roster. */
    const { checkEmailSyntax } = require('../src/email-syntax');
    for (const g of ['jane@example.com', 'j.smith+union@mail.example.co.uk', "o'brien@example.org", 'x_y-z@my-local.us']) {
      assert.ok(checkEmailSyntax(g).ok, `validator accepts ${g}`);
    }
    for (const b of ['jane@gmail', 'jane@@example.com', 'jane smith@example.com', 'jane@', '@example.com',
      'jane@.com', 'jane@example.', 'jane@example..com', 'jane.example.com', 'jane@example.c',
      'jane@example.123', 'jane@-example.com', '.jane@example.com', 'ja..ne@example.com']) {
      const c = checkEmailSyntax(b);
      assert.ok(!c.ok && c.reason, `validator rejects ${b} with a reason`);
    }

    const membersBefore = db.prepare('SELECT COUNT(*) n FROM members').get().n;
    r = await req('POST', '/admin/members/import', {
      roster: [
        'Hank H, hank@example.org, 20',     // valid — must import
        'Ivy I, ivy@gmail, 21',             // missing .com/.org ending
        'Jack J, jack@@example.com, 22',    // double @@
        'Kim K, kim smith@example.com, 23', // space in address
        'Lee L, lee@.com, 24',              // empty domain section
        'Mona M, mona.example.com, 25',     // missing @
        'Nora N (paper), , 26',             // blank email — paper path, must import
        ', orphan@example.com, 27',         // missing name
      ].join('\n'),
    });
    assert.strictEqual(r.status, 200, 'import with rejected rows renders the report page (no silent redirect)');
    assert.ok(r.text.includes('Import report'), 'report page shown');
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM members').get().n, membersBefore + 2,
      'only the valid row and the blank-email (paper) row were imported');
    assert.ok(db.prepare('SELECT id FROM members WHERE name=?').get('Hank H'), 'valid row imported alongside rejects');
    assert.ok(db.prepare('SELECT id FROM members WHERE name=?').get('Nora N (paper)'), 'blank email is NOT a format error (paper path)');
    for (const name of ['Ivy I', 'Jack J', 'Kim K', 'Lee L', 'Mona M']) {
      assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM members WHERE name=?').get(name).n, 0, `${name} not imported`);
      assert.ok(r.text.includes(name), `${name} listed on the report`);
    }
    assert.ok(r.text.includes('ivy@gmail'), 'rejected address shown on the report');
    assert.ok(r.text.includes('has no ending'), 'missing-TLD reason shown');
    assert.ok(r.text.includes('more than one'), 'double-@ reason shown');
    assert.ok(r.text.includes('missing the member name'), 'nameless row reported, not silently skipped');
    assert.ok(r.text.includes('Ivy I, ivy@gmail, 21'), 'rejected raw rows pre-filled for fix-and-reimport');
    /* a fully-valid upload keeps the original flash + redirect behavior */
    r = await req('POST', '/admin/members/import', { roster: 'Olive O, olive@example.net, 28' });
    assert.strictEqual(r.status, 302, 'clean import still redirects to the roster (unchanged path)');

    /* 15. MEMBER-EDIT EMAIL VALIDATION — same gate, whole save rejected */
    const olive = db.prepare('SELECT * FROM members WHERE name=?').get('Olive O');
    await req('POST', `/admin/members/${olive.id}/update`, { email: 'olive@broken', good_standing: '0', needs_paper_ballot: '1' });
    const oliveAfter = db.prepare('SELECT * FROM members WHERE id=?').get(olive.id);
    assert.strictEqual(oliveAfter.email, 'olive@example.net', 'invalid email edit not saved');
    assert.strictEqual(oliveAfter.good_standing, 1, 'whole update rejected — standing flag unchanged too');
    assert.strictEqual(oliveAfter.needs_paper_ballot, 0, 'whole update rejected — paper flag unchanged too');
    await req('POST', `/admin/members/${olive.id}/update`, { email: 'olive@example.org', good_standing: '1', needs_paper_ballot: '0' });
    assert.strictEqual(db.prepare('SELECT email FROM members WHERE id=?').get(olive.id).email, 'olive@example.org', 'valid email edit saved');
    await req('POST', `/admin/members/${olive.id}/update`, { email: '', good_standing: '1', needs_paper_ballot: '0' });
    assert.strictEqual(db.prepare('SELECT email FROM members WHERE id=?').get(olive.id).email, null, 'clearing the email (paper path) still allowed');

    /* 16. PLATFORM OWNER PAGE — key-gated, counts only, no PII.
     * An ordinary committee session must NOT open it; only PLATFORM_OWNER_KEY
     * (login form or X-Platform-Key header) does. */
    r = await req('GET', '/platform'); // signed-in ADMIN session, no platform auth
    assert.strictEqual(r.status, 200);
    assert.ok(r.text.includes('Platform access'), 'committee session alone gets the key form, never the stats');
    assert.ok(!r.text.includes('Members on roster'), 'no stats leak to a committee-only session');
    r = await reqHeaders('GET', '/platform', {});
    assert.ok(r.text.includes('Platform access'), 'anonymous request gets the key form');
    r = await reqHeaders('GET', '/platform', { 'x-platform-key': 'wrong-key-wrong-key' });
    assert.ok(r.text.includes('Platform access') && !r.text.includes('Members on roster'), 'wrong header key gets the form, not the stats');
    r = await req('POST', '/platform/auth', { key: 'wrong-key-wrong-key' });
    assert.strictEqual(r.status, 302, 'wrong key on the form is bounced');
    r = await req('GET', '/platform');
    assert.ok(r.text.includes('Platform access'), 'still locked after a wrong key');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='platform.auth_failed'").get().n >= 1, 'failed platform sign-in is audited (key not recorded)');
    assert.strictEqual(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE detail LIKE '%wrong-key-wrong-key%'").get().n, 0, 'submitted key never lands in the audit log');

    r = await reqHeaders('GET', '/platform', { 'x-platform-key': PLATFORM_KEY });
    assert.ok(r.text.includes('Instance stats &amp; recovery'), 'correct X-Platform-Key header opens the stats page');
    assert.ok(r.text.includes('Members on roster'), 'roster size shown as a count');
    assert.ok(r.text.includes('85.7%'), 'turnout rate computed from the eligibility snapshot (6 of 7)');
    assert.ok(r.text.includes('2026 Officer Election'), 'sealed archive listed with election title');
    for (const pii of ['Alice', 'Bob B', 'a@x.test', 'Hank H', 'hank@example.org', 'chair@']) {
      assert.ok(!r.text.includes(pii), `platform page never shows PII (${pii})`);
    }
    r = await req('POST', '/platform/auth', { key: PLATFORM_KEY });
    assert.strictEqual(r.location, '/platform', 'correct key on the form signs in');
    r = await req('GET', '/platform');
    assert.ok(r.text.includes('Instance stats &amp; recovery'), 'session flag opens the stats page');

    /* 17. SEALED ARCHIVE DOWNLOAD from the platform page */
    let dl = await reqBinary(`/platform/archives/${archRow.id}/download`, {});
    assert.strictEqual(dl.status, 302, 'unauthenticated archive download is refused');
    dl = await reqBinary(`/platform/archives/${archRow.id}/download`, { 'x-platform-key': PLATFORM_KEY });
    assert.strictEqual(dl.status, 200, 'platform owner can download the archive');
    const dlArchive = JSON.parse(decryptSealed(dl.buf, BACKUP_KEY_HEX).toString('utf8'));
    assert.strictEqual(dlArchive.election.id, eid, 'downloaded archive is the tallied election');
    assert.strictEqual(dlArchive.encrypted_ballots.length, 6, 'downloaded archive still holds only ENCRYPTED ballots');

    /* 18. ACCOUNT RECOVERY EMAIL management (admin Accounts page) */
    r = await req('GET', '/admin/users');
    assert.ok(r.text.includes('Recovery email'), 'accounts page renders the recovery-email column');
    r = await req('GET', '/login', null, false);
    assert.ok(r.text.includes('Forgot your password?'), 'sign-in page links to the reset flow');
    const chairId = db.prepare("SELECT id FROM users WHERE username='chair'").get().id;
    await req('POST', `/admin/users/${chairId}/email`, { email: 'chair@broken' });
    assert.strictEqual(db.prepare('SELECT email FROM users WHERE id=?').get(chairId).email, null, 'malformed recovery email rejected');
    await req('POST', `/admin/users/${chairId}/email`, { email: 'chair@example.org' });
    assert.strictEqual(db.prepare('SELECT email FROM users WHERE id=?').get(chairId).email, 'chair@example.org', 'recovery email saved');
    await req('POST', '/admin/users', { display_name: 'Obs', username: 'obs1', password: 'observer-pass-1', role: 'observer', email: 'obs@example.org' });
    assert.strictEqual(db.prepare("SELECT email FROM users WHERE username='obs1'").get().email, 'obs@example.org', 'recovery email stored at account creation');

    /* 18b. FORGOT-PASSWORD without SMTP: nothing sent, no token minted,
     * the visitor is pointed at platform support. */
    r = await req('GET', '/forgot-password', null, false);
    assert.ok(r.text.includes('Email delivery is not configured'), 'forgot-password explains the no-SMTP path');
    r = await req('POST', '/forgot-password', { username: 'chair' }, false);
    assert.strictEqual(r.status, 302);
    assert.strictEqual(db.prepare('SELECT reset_token_hash FROM users WHERE id=?').get(chairId).reset_token_hash, null, 'no reset token minted when nothing can be emailed');

    /* 19. ONE-TIME RESET LINK from the platform owner + full reset flow.
     * The password is chosen by the account holder on the token page; no
     * plaintext password or token is ever stored or logged. */
    r = await req('POST', '/platform/reset-link', { username: 'nobody-here' });
    assert.strictEqual(r.status, 302, 'unknown username refused');
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM users WHERE reset_token_hash IS NOT NULL').get().n, 0, 'no token minted for unknown accounts');
    r = await req('POST', '/platform/reset-link', { username: 'chair' });
    const resetMatch = r.text.match(/\/reset-password\?token=([0-9a-f]{32})/);
    assert.ok(resetMatch, 'one-time reset link displayed exactly once');
    const resetToken = resetMatch[1];
    assert.ok(!db.serialize().toString('latin1').includes(resetToken), 'reset token stored only as a hash');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='platform.reset_link_generated'").get().n >= 1, 'reset-link generation is audited');
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM audit_log WHERE detail LIKE ?').get(`%${resetToken}%`).n, 0, 'token plaintext never appears in the audit log');

    r = await req('GET', `/reset-password?token=${resetToken}`, null, false);
    assert.strictEqual(r.status, 200);
    assert.ok(r.text.includes('chair'), 'reset page names the account being reset');
    r = await req('POST', '/reset-password', { token: resetToken, password: 'short', password_confirm: 'short' }, false);
    assert.ok(r.status === 302 && r.location.includes('/reset-password'), 'short password rejected, token still live');
    r = await req('POST', '/reset-password', { token: resetToken, password: 'new-committee-pass-9', password_confirm: 'different-pass-9' }, false);
    assert.ok(r.status === 302 && r.location.includes('/reset-password'), 'mismatched confirmation rejected, token still live');
    r = await req('POST', '/reset-password', { token: resetToken, password: 'new-committee-pass-9', password_confirm: 'new-committee-pass-9' }, false);
    assert.strictEqual(r.location, '/login', 'successful reset lands on sign-in');
    assert.strictEqual(db.prepare('SELECT reset_token_hash FROM users WHERE id=?').get(chairId).reset_token_hash, null, 'token consumed on success');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='auth.password_reset_completed'").get().n >= 1, 'reset completion is audited');
    r = await req('GET', `/reset-password?token=${resetToken}`, null, false);
    assert.strictEqual(r.status, 400, 'used reset token rejected');
    r = await req('POST', '/login', { username: 'chair', password: 'committee-pass-1' });
    assert.strictEqual(r.location, '/login', 'old password no longer works');
    r = await req('POST', '/login', { username: 'chair', password: 'new-committee-pass-9' });
    assert.strictEqual(r.location, '/admin', 'new password signs in');

    console.log('\nALL SMOKE TESTS PASSED ✔');
    console.log(`  Election #${eid}: 6 ballots, Smith elected (majority), dues adopted (2/3).`);
    console.log('  Verified: approval gate, one-time shares, hashed credentials, unlinkable ballots,');
    console.log('  date-only redemption, double-vote rejection, 3-of-5 threshold tally, audit chain, archive.');
    console.log('  Verified: email-verification gate (block/verify/single-use token/reset-on-change),');
    console.log('  Florida PERC ratification hard stop (block, variance path, test/non-ratification/non-FL unaffected),');
    console.log('  roster-import email-syntax gate (bad rows reported with reasons, good rows imported,');
    console.log('  blank email = paper path untouched, member-edit rejects malformed addresses).');
    console.log('  Verified: automatic sealed archive at tally (encrypted under BACKUP_KEY, no shares,');
    console.log('  no credential plaintext), platform page gated by PLATFORM_OWNER_KEY only (committee');
    console.log('  session refused, counts-only stats, no PII, archive download), and password recovery');
    console.log('  (hash-only single-use expiring tokens, platform one-time link, old password dies).');
  } finally {
    server.close();
    fs.rmSync(process.env.DATA_DIR, { recursive: true, force: true });
  }
})().catch((e) => { console.error('SMOKE TEST FAILED:', e); process.exit(1); });
