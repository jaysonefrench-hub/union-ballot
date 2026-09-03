/**
 * scripts/smoke-test.js — Full end-to-end election against the live server.
 * Verifies: platform bootstrap (PLATFORM_OWNER_KEY-gated /platform/setup,
 * account sign-in) → create Local A + its first committee admin → roster →
 * create (with IAFF approval gate) → key ceremony → credentials → open →
 * 6 ballots cast → close → tally with 3-of-5 shares → majority/runoff math →
 * anonymity properties of stored data → roster-import email-syntax gate
 * (report of rejected rows) → member-edit email gate → automatic sealed
 * archive at tally → platform dashboard (accounts only, per-local stats +
 * rollup, counts only, archive download, whole-DB backup) → committee
 * password reset (hash-only tokens) → DEMO/TEST skip-email-verify (binding
 * still gated; TEST+demo allows unverified syntactically-valid emails; PERC
 * FL binding still blocked) → MULTI-LOCAL ISOLATION (Local B's committee/
 * observer structurally cannot see or affect Local A's roster, elections,
 * credentials, accounts, audit chain, or archives — and vice versa; the
 * cross-local credential-issuance bug stays dead; per-local audit chains
 * verify independently) → MIGRATION (a pre-multi-tenant database boots,
 * backfills everything into one sensibly-named default local, keeps the old
 * committee login working, and leaves nothing orphaned).
 */
'use strict';
const crypto = require('crypto');
process.env.DATA_DIR = require('path').join(__dirname, '..', 'data-test');
process.env.PORT = '3999';
/* The test creates a binding (non-test) election, and getReissueKey() refuses
 * to auto-generate a key once one exists — so supply a throwaway key, exactly
 * as a real deployment would via the environment. */
process.env.REISSUE_KEY = process.env.REISSUE_KEY || crypto.randomBytes(32).toString('hex');
/* Exercise the key-gated platform bootstrap and encrypted-at-rest archives. */
const PLATFORM_KEY = 'platform-owner-test-key-0123456789';
process.env.PLATFORM_OWNER_KEY = PLATFORM_KEY;
const BACKUP_KEY_HEX = crypto.randomBytes(32).toString('hex');
process.env.BACKUP_KEY = BACKUP_KEY_HEX;
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
fs.rmSync(process.env.DATA_DIR, { recursive: true, force: true });
const MIGRATE_DIR = path.join(__dirname, '..', 'data-test-migrate');
fs.rmSync(MIGRATE_DIR, { recursive: true, force: true });

const app = require('../server');
const { db } = require('../src/db');
const assert = require('assert');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const BASE = 'http://localhost:3999';

/* Separate cookie jars so committee A, committee B, observers, and the
 * platform administrator hold genuinely independent sessions. */
function jar() { return { cookie: '' }; }
const chairJar = jar();     // Local A committee admin
const beeJar = jar();       // Local B committee admin
const obsBJar = jar();      // Local B observer
const platformJar = jar();  // platform administrator

async function req(method, path, body, session = chairJar) {
  const headers = {};
  if (session && session.cookie) headers.Cookie = session.cookie;
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
  if (setc && session) session.cookie = setc.split(';')[0]; // anonymous voter requests (session=null) never touch a jar
  return { status: r.status, text: await r.text(), location: r.headers.get('location') };
}

/* Binary download with an optional session jar. */
async function reqBinary(path, session) {
  const headers = {};
  if (session && session.cookie) headers.Cookie = session.cookie;
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
    /* 0. PLATFORM BOOTSTRAP — the first platform administrator is created at
     * /platform/setup, authorized by PLATFORM_OWNER_KEY (which is set here,
     * as on every pre-multi-tenant deployment). */
    let r = await req('GET', '/platform', null, null);
    assert.strictEqual(r.status, 302, 'platform page redirects while no platform admin exists');
    assert.ok(r.location.includes('/platform/setup'), 'redirects to platform setup');
    r = await req('GET', '/setup', null, null);
    assert.ok(r.status === 302 && r.location.includes('/platform/setup'), 'legacy /setup points at the platform bootstrap on a fresh instance');
    r = await req('GET', '/login', null, null);
    assert.ok(r.status === 302 && r.location.includes('/platform/setup'), 'login redirects to bootstrap on a fresh instance');
    r = await req('GET', '/platform/setup', null, null);
    assert.ok(r.text.includes('PLATFORM_OWNER_KEY'), 'setup form requires the configured key');

    r = await req('POST', '/platform/setup', { key: 'wrong-key-wrong-key', username: 'intruder', password: 'intruder-pass-1', display_name: 'X' }, platformJar);
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM platform_users').get().n, 0, 'wrong key creates no platform account');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='platform.setup_key_rejected'").get().n >= 1, 'rejected setup key is audited');
    assert.strictEqual(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE detail LIKE '%wrong-key-wrong-key%'").get().n, 0, 'submitted key never lands in the audit log');

    r = await req('POST', '/platform/setup', { key: PLATFORM_KEY, username: 'operator', password: 'platform-pass-01', display_name: 'Platform Operator' }, platformJar);
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM platform_users').get().n, 1, 'platform administrator created with the correct key');
    const padm = db.prepare('SELECT * FROM platform_users LIMIT 1').get();
    assert.ok(padm.password_hash.startsWith('$2'), 'platform password stored as bcrypt hash only');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='platform.admin_created' AND local_id IS NULL").get().n >= 1, 'platform account creation audited on the platform chain');

    r = await req('POST', '/platform/auth', { username: 'operator', password: 'wrong-password-1' }, platformJar);
    r = await req('GET', '/platform', null, platformJar);
    assert.ok(r.text.includes('Platform sign-in') && !r.text.includes('Members on rosters'), 'wrong password stays locked out');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='platform.auth_failed'").get().n >= 1, 'failed platform sign-in is audited (values not recorded)');
    r = await req('POST', '/platform/auth', { username: 'operator', password: 'platform-pass-01' }, platformJar);
    assert.strictEqual(r.location, '/platform', 'platform sign-in works');

    /* 1. CREATE LOCAL A + its first committee-admin account (the multi-local
     * heir to the old one-time /setup), then sign the committee in. */
    r = await req('POST', '/platform/locals', {
      name: 'Buckeye Fire Fighters Local 100', local_number: '100', jurisdiction: '',
      admin_display_name: 'Committee Chair', admin_username: 'chair', admin_password: 'committee-pass-1',
    }, platformJar);
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM locals').get().n, 0, 'local creation requires a jurisdiction');
    r = await req('POST', '/platform/locals', {
      name: 'Buckeye Fire Fighters Local 100', local_number: '100', jurisdiction: 'OH',
      admin_display_name: 'Committee Chair', admin_username: 'chair', admin_password: 'committee-pass-1',
    }, platformJar);
    const localA = db.prepare("SELECT * FROM locals WHERE name='Buckeye Fire Fighters Local 100'").get();
    assert.ok(localA, 'Local A created');
    const chairRow = db.prepare("SELECT * FROM users WHERE username='chair'").get();
    assert.strictEqual(chairRow.local_id, localA.id, 'first committee account belongs to the new local');
    assert.strictEqual(chairRow.role, 'admin');
    const firstAEntry = db.prepare('SELECT * FROM audit_log WHERE local_id=? ORDER BY id ASC LIMIT 1').get(localA.id);
    assert.strictEqual(firstAEntry.event, 'local.created', "the local's audit chain begins with its own creation record");
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='platform.local_created' AND local_id IS NULL").get().n >= 1, 'local creation also recorded on the platform chain');

    /* A committee session must NOT be able to create locals or reset links. */
    await req('POST', '/login', { username: 'chair', password: 'committee-pass-1' }, chairJar);
    r = await req('POST', '/platform/locals', { name: 'Rogue Local', jurisdiction: 'OH', admin_username: 'rogue', admin_password: 'rogue-pass-01', admin_display_name: 'R' }, chairJar);
    assert.strictEqual(r.status, 302, 'committee session bounced from platform local creation');
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM locals').get().n, 1, 'no local created by a committee session');

    /* 2. Roster: 6 electronic voters + 1 paper member */
    const roster = ['Alice A, a@x.test, 1', 'Bob B, b@x.test, 2', 'Cara C, c@x.test, 3',
      'Dan D, d@x.test, 4', 'Eve E, e@x.test, 5', 'Fay F, f@x.test, 6', 'Gus G (no email), , 7'].join('\n');
    await req('POST', '/admin/members/import', { roster }, chairJar);
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM members').get().n, 7, 'roster imported');
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM members WHERE local_id=?').get(localA.id).n, 7, 'every imported member carries Local A\u2019s local_id');

    /* 2b. Email verification: everyone with an email starts UNVERIFIED */
    assert.strictEqual(db.prepare("SELECT COUNT(*) n FROM members WHERE email IS NOT NULL AND email_verified=1").get().n, 0,
      'imported members start with unverified emails');

    /* 3. IAFF approval gate: officer election WITHOUT approval must be rejected */
    r = await req('POST', '/admin/elections/new', {
      title: 'Should Fail', kind: 'officer_election', jurisdiction: 'OH',
      race_title: 'President', race_seats: '1', race_threshold: 'majority', race_candidates: 'X\nY',
      key_shares_total: '5', key_threshold: '3', keyholders: '',
    }, chairJar);
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM elections').get().n, 0, 'approval gate blocks unapproved officer election');

    /* 3b. Jurisdiction is required */
    r = await req('POST', '/admin/elections/new', {
      title: 'No Jurisdiction', kind: 'other', jurisdiction: '',
      race_title: 'Q', race_seats: '1', race_threshold: 'majority', race_candidates: 'Yes\nNo',
      key_shares_total: '5', key_threshold: '3', keyholders: '',
    }, chairJar);
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
    }, chairJar);
    const shares = [...r.text.matchAll(/SHARE-\d+-[0-9a-f]+/g)].map((m) => m[0]);
    assert.strictEqual(shares.length, 5, 'five key shares displayed once');
    const eid = db.prepare('SELECT id FROM elections ORDER BY id DESC LIMIT 1').get().id;
    assert.strictEqual(db.prepare('SELECT local_id FROM elections WHERE id=?').get(eid).local_id, localA.id, 'election belongs to Local A');

    /* 4b. Credential issuance must be BLOCKED while electronic-path emails are unverified */
    r = await req('POST', `/admin/elections/${eid}/issue-credentials`, {}, chairJar);
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
      const page = await req('POST', `/admin/members/${m.id}/send-verification`, {}, chairJar);
      const match = page.text.match(/\/verify-email\?token=([0-9a-f]{32})/);
      assert.ok(match, `one-time verification link displayed for ${m.name}`);
      if (!firstToken) firstToken = match[1];
      /* token stored only as a hash, never in plaintext */
      assert.ok(!db.serialize().toString('latin1').includes(match[1]), 'verification token plaintext never stored');
      const v = await req('GET', `/verify-email?token=${match[1]}`, null, null);
      assert.ok(v.text.includes('confirmed'), `${m.name} email verified via link`);
    }
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM members WHERE email_verified=1').get().n, 6, 'all six emails verified');
    /* tokens are single-use and bad tokens are rejected */
    let v = await req('GET', `/verify-email?token=${firstToken}`, null, null);
    assert.strictEqual(v.status, 400, 'used verification token rejected');
    v = await req('GET', '/verify-email?token=deadbeefdeadbeefdeadbeefdeadbeef', null, null);
    assert.strictEqual(v.status, 400, 'unknown verification token rejected');
    /* changing a member's email resets verification */
    const alice = emembers[0];
    await req('POST', `/admin/members/${alice.id}/update`, { email: 'new-a@x.test', good_standing: '1', needs_paper_ballot: '0' }, chairJar);
    assert.strictEqual(db.prepare('SELECT email_verified FROM members WHERE id=?').get(alice.id).email_verified, 0, 'email change resets verification');
    /* restore and re-verify so issuance can proceed */
    await req('POST', `/admin/members/${alice.id}/update`, { email: 'a@x.test', good_standing: '1', needs_paper_ballot: '0' }, chairJar);
    const relink = await req('POST', `/admin/members/${alice.id}/send-verification`, {}, chairJar);
    await req('GET', relink.text.match(/\/verify-email\?token=[0-9a-f]{32}/)[0], null, null);

    /* 5. Issue credentials (no SMTP → one-time export) and capture them */
    r = await req('POST', `/admin/elections/${eid}/issue-credentials`, {}, chairJar);
    const creds = [...r.text.matchAll(/[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}/g)].map((m) => m[0]);
    assert.strictEqual(creds.length, 6, 'six electronic credentials issued (paper member excluded)');
    assert.ok(r.text.includes('Gus G'), 'paper-ballot member listed for alternative method');
    /* plaintext credentials must NOT be in the database */
    const dbdump = db.serialize().toString('latin1');
    for (const c of creds) assert.ok(!dbdump.includes(c.replace(/-/g, '')) && !dbdump.includes(c), 'credential plaintext never stored');

    /* 6. Open voting */
    await req('POST', `/admin/elections/${eid}/open`, {}, chairJar);

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
      const rr = await req('POST', '/vote/cast', body, null);
      assert.ok(rr.text.includes('Your ballot was cast'), `ballot ${i + 1} cast`);
      assert.ok(!rr.text.includes('Smith') && !rr.text.includes('Yes —'), 'confirmation never echoes choices');
    }

    /* 8. Double-vote must be rejected */
    const dbl = await req('POST', '/vote', { credential: creds[0] }, null);
    assert.strictEqual(dbl.status, 302, 'reused credential bounced back');

    /* 9. Anonymity properties of stored data */
    const brows = db.prepare('SELECT * FROM ballots').all();
    assert.strictEqual(brows.length, 6, 'six sealed ballots');
    for (const b of brows) {
      assert.deepStrictEqual(Object.keys(b).sort(), ['election_id', 'id', 'payload'], 'ballot rows carry nothing but id/election/ciphertext — no local_id, no member data');
      assert.ok(!b.payload.includes('Smith'), 'ballot content encrypted');
    }
    const credRows = db.prepare('SELECT * FROM credentials').all();
    assert.ok(credRows.every((c) => !('ballot_id' in c)), 'credentials never reference ballots');
    assert.ok(credRows.filter((c) => c.redeemed).every((c) => /^\d{4}-\d{2}-\d{2}$/.test(c.redeemed_on)), 'redemption recorded as date only, no time');

    /* 10. Tally must fail with too few shares, succeed with 3 of 5 */
    await req('POST', `/admin/elections/${eid}/close`, {}, chairJar);
    let t = await req('POST', `/admin/elections/${eid}/tally`, { share: [shares[0], shares[2]] }, chairJar);
    assert.ok(t.location && t.location.includes('/tally'), 'two shares rejected (threshold is 3)');
    t = await req('POST', `/admin/elections/${eid}/tally`, { share: [shares[0], shares[2], shares[4]] }, chairJar);

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
    const chainA = verifyAuditChain(localA.id);
    assert.ok(chainA.ok, 'Local A audit chain verifies');
    const castLogs = db.prepare("SELECT detail FROM audit_log WHERE event='vote.ballot_cast'").all();
    assert.strictEqual(castLogs.length, 6);
    assert.ok(castLogs.every((l) => !/Alice|Bob|Cara|Dan|Eve|Fay/.test(l.detail)), 'cast events are anonymous');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='vote.ballot_cast' AND local_id=?").get(localA.id).n === 6, 'ballot-cast counter events land on the owning local\u2019s chain');

    /* 12. Records archive exports */
    const arch = await req('GET', `/admin/elections/${eid}/archive`, null, chairJar);
    const archive = JSON.parse(arch.text);
    assert.strictEqual(archive.encrypted_ballots.length, 6, 'archive preserves encrypted ballots');
    assert.ok(archive.audit_chain_verification.ok);
    assert.strictEqual(archive.local.id, localA.id, 'archive names its owning local');
    assert.ok(archive.audit_log.every((row) => row.local_id === localA.id), 'archived audit log is the local\u2019s own chain only');

    /* 12b. AUTOMATIC SEALED ARCHIVE AT TALLY — written without anyone asking,
     * encrypted at rest under BACKUP_KEY, listed by metadata only. */
    const archRow = db.prepare('SELECT * FROM archives WHERE election_id=?').get(eid);
    assert.ok(archRow, 'tally automatically stored a sealed records archive');
    assert.strictEqual(archRow.ballot_count, 6, 'archive metadata records the encrypted-ballot count');
    assert.strictEqual(archRow.encrypted, 1, 'archive is encrypted at rest (BACKUP_KEY set)');
    assert.strictEqual(archRow.election_title, '2026 Officer Election');
    assert.strictEqual(archRow.local_id, localA.id, 'archive metadata records the owning local');
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
    await req('POST', '/admin/elections/new', { ...baseVote, title: 'FL TA Ratification (no variance)', kind: 'contract_ratification', jurisdiction: 'FL' }, chairJar);
    assert.strictEqual(electionCount(), n0, 'binding FL electronic ratification blocked without PERC variance ack');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.create_blocked_perc'").get().n >= 1, 'PERC block is audited');

    /* 13b. Binding FL ratification WITH the recorded variance ack → allowed, flag stored */
    await req('POST', '/admin/elections/new', { ...baseVote, title: 'FL TA Ratification (variance claimed)', kind: 'contract_ratification', jurisdiction: 'FL', perc_variance_ack: '1', perc_variance_ref: 'PERC variance order 2026-03-15' }, chairJar);
    assert.strictEqual(electionCount(), n0 + 1, 'FL ratification allowed when committee records a PERC variance');
    const flVar = db.prepare('SELECT * FROM elections ORDER BY id DESC LIMIT 1').get();
    assert.strictEqual(flVar.perc_variance_ack, 1, 'variance acknowledgment stored on the election');
    assert.strictEqual(flVar.perc_variance_ref, 'PERC variance order 2026-03-15', 'variance reference stored');
    assert.strictEqual(flVar.demo_skip_email_verify, 0, 'binding FL ratification never stores demo skip-email-verify');

    /* 13c. FL TEST-election ratification → allowed without a variance */
    await req('POST', '/admin/elections/new', { ...baseVote, title: 'FL TA Ratification (test run)', kind: 'contract_ratification', jurisdiction: 'FL', is_test: '1' }, chairJar);
    assert.strictEqual(electionCount(), n0 + 2, 'FL ratification test election allowed without variance');
    const flTest = db.prepare("SELECT * FROM elections WHERE title=?").get('FL TA Ratification (test run)');
    assert.strictEqual(flTest.is_test, 1);
    assert.strictEqual(flTest.demo_skip_email_verify, 1, 'new TEST elections default demo_skip_email_verify ON');

    /* 13d. FL NON-ratification votes are NOT blocked (bylaws, officer election) */
    await req('POST', '/admin/elections/new', { ...baseVote, title: 'FL Bylaw Amendment', kind: 'bylaw_amendment', jurisdiction: 'FL' }, chairJar);
    assert.strictEqual(electionCount(), n0 + 3, 'FL bylaw amendment not blocked');
    await req('POST', '/admin/elections/new', { ...baseVote, title: 'FL Officer Election', kind: 'officer_election', jurisdiction: 'FL', iaff_legal_approval: 'IAFF Legal Dept letter 2026-06-01' }, chairJar);
    assert.strictEqual(electionCount(), n0 + 4, 'FL officer election not blocked by PERC gate');

    /* 13e. Non-FL ratification → not blocked */
    await req('POST', '/admin/elections/new', { ...baseVote, title: 'OH TA Ratification', kind: 'contract_ratification', jurisdiction: 'OH' }, chairJar);
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
    }, chairJar);
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
    r = await req('POST', '/admin/members/import', { roster: 'Olive O, olive@example.net, 28' }, chairJar);
    assert.strictEqual(r.status, 302, 'clean import still redirects to the roster (unchanged path)');

    /* 15. MEMBER-EDIT EMAIL VALIDATION — same gate, whole save rejected */
    const olive = db.prepare('SELECT * FROM members WHERE name=?').get('Olive O');
    await req('POST', `/admin/members/${olive.id}/update`, { email: 'olive@broken', good_standing: '0', needs_paper_ballot: '1' }, chairJar);
    const oliveAfter = db.prepare('SELECT * FROM members WHERE id=?').get(olive.id);
    assert.strictEqual(oliveAfter.email, 'olive@example.net', 'invalid email edit not saved');
    assert.strictEqual(oliveAfter.good_standing, 1, 'whole update rejected — standing flag unchanged too');
    assert.strictEqual(oliveAfter.needs_paper_ballot, 0, 'whole update rejected — paper flag unchanged too');
    await req('POST', `/admin/members/${olive.id}/update`, { email: 'olive@example.org', good_standing: '1', needs_paper_ballot: '0' }, chairJar);
    assert.strictEqual(db.prepare('SELECT email FROM members WHERE id=?').get(olive.id).email, 'olive@example.org', 'valid email edit saved');
    await req('POST', `/admin/members/${olive.id}/update`, { email: '', good_standing: '1', needs_paper_ballot: '0' }, chairJar);
    assert.strictEqual(db.prepare('SELECT email FROM members WHERE id=?').get(olive.id).email, null, 'clearing the email (paper path) still allowed');

    /* 16. PLATFORM DASHBOARD — platform accounts only, counts only, no PII.
     * An ordinary committee session must NOT open it; only a platform
     * administrator sign-in does. */
    r = await req('GET', '/platform', null, chairJar); // signed-in COMMITTEE session, no platform auth
    assert.strictEqual(r.status, 200);
    assert.ok(r.text.includes('Platform sign-in'), 'committee session alone gets the sign-in form, never the stats');
    assert.ok(!r.text.includes('Members on rosters'), 'no stats leak to a committee-only session');
    r = await req('GET', '/platform', null, null);
    assert.ok(r.text.includes('Platform sign-in'), 'anonymous request gets the sign-in form');

    r = await req('GET', '/platform', null, platformJar);
    assert.ok(r.text.includes('Locals, stats &amp; recovery'), 'platform administrator session opens the dashboard');
    assert.ok(r.text.includes('Members on rosters'), 'roster size shown as a count');
    assert.ok(r.text.includes('85.7%'), 'turnout rate computed from the eligibility snapshot (6 of 7)');
    assert.ok(r.text.includes('2026 Officer Election'), 'sealed archive listed with election title');
    assert.ok(r.text.includes('Buckeye Fire Fighters Local 100'), 'per-local breakdown names the local');
    for (const pii of ['Alice', 'Bob B', 'a@x.test', 'Hank H', 'hank@example.org', 'chair@']) {
      assert.ok(!r.text.includes(pii), `platform page never shows PII (${pii})`);
    }

    /* 17. SEALED ARCHIVE DOWNLOAD from the platform page */
    let dl = await reqBinary(`/platform/archives/${archRow.id}/download`, null);
    assert.strictEqual(dl.status, 302, 'unauthenticated archive download is refused');
    dl = await reqBinary(`/platform/archives/${archRow.id}/download`, chairJar);
    assert.strictEqual(dl.status, 302, 'committee session cannot download from the platform page');
    dl = await reqBinary(`/platform/archives/${archRow.id}/download`, platformJar);
    assert.strictEqual(dl.status, 200, 'platform administrator can download the archive');
    const dlArchive = JSON.parse(decryptSealed(dl.buf, BACKUP_KEY_HEX).toString('utf8'));
    assert.strictEqual(dlArchive.election.id, eid, 'downloaded archive is the tallied election');
    assert.strictEqual(dlArchive.encrypted_ballots.length, 6, 'downloaded archive still holds only ENCRYPTED ballots');

    /* 17b. WHOLE-DATABASE BACKUP moved to the platform role: committees have
     * no backup route at all any more (it would span every local). */
    r = await req('GET', '/admin/backup', null, chairJar);
    assert.strictEqual(r.status, 404, 'committee whole-database backup route no longer exists');
    dl = await reqBinary('/platform/backup', chairJar);
    assert.strictEqual(dl.status, 302, 'committee session cannot pull the platform backup');
    dl = await reqBinary('/platform/backup', platformJar);
    assert.strictEqual(dl.status, 200, 'platform administrator downloads the encrypted backup');
    const dbPlain = decryptSealed(dl.buf, BACKUP_KEY_HEX);
    assert.ok(dbPlain.subarray(0, 15).toString('latin1').startsWith('SQLite format 3'), 'backup decrypts to a SQLite database');

    /* 18. ACCOUNT RECOVERY EMAIL management (admin Accounts page) */
    r = await req('GET', '/admin/users', null, chairJar);
    assert.ok(r.text.includes('Recovery email'), 'accounts page renders the recovery-email column');
    r = await req('GET', '/login', null, null);
    assert.ok(r.text.includes('Forgot your password?'), 'sign-in page links to the reset flow');
    const chairId = db.prepare("SELECT id FROM users WHERE username='chair'").get().id;
    await req('POST', `/admin/users/${chairId}/email`, { email: 'chair@broken' }, chairJar);
    assert.strictEqual(db.prepare('SELECT email FROM users WHERE id=?').get(chairId).email, null, 'malformed recovery email rejected');
    await req('POST', `/admin/users/${chairId}/email`, { email: 'chair@example.org' }, chairJar);
    assert.strictEqual(db.prepare('SELECT email FROM users WHERE id=?').get(chairId).email, 'chair@example.org', 'recovery email saved');
    await req('POST', '/admin/users', { display_name: 'Obs', username: 'obs1', password: 'observer-pass-1', role: 'observer', email: 'obs@example.org' }, chairJar);
    assert.strictEqual(db.prepare("SELECT email FROM users WHERE username='obs1'").get().email, 'obs@example.org', 'recovery email stored at account creation');
    assert.strictEqual(db.prepare("SELECT local_id FROM users WHERE username='obs1'").get().local_id, localA.id, 'observer account created inside the committee\u2019s own local');

    /* 18b. FORGOT-PASSWORD without SMTP: nothing sent, no token minted,
     * the visitor is pointed at platform support. */
    r = await req('GET', '/forgot-password', null, null);
    assert.ok(r.text.includes('Email delivery is not configured'), 'forgot-password explains the no-SMTP path');
    r = await req('POST', '/forgot-password', { username: 'chair' }, null);
    assert.strictEqual(r.status, 302);
    assert.strictEqual(db.prepare('SELECT reset_token_hash FROM users WHERE id=?').get(chairId).reset_token_hash, null, 'no reset token minted when nothing can be emailed');

    /* 19. ONE-TIME RESET LINK from the platform administrator + full reset
     * flow. The password is chosen by the account holder on the token page;
     * no plaintext password or token is ever stored or logged. */
    r = await req('POST', '/platform/reset-link', { username: 'chair' }, chairJar);
    assert.strictEqual(r.status, 302, 'committee session cannot generate platform reset links');
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM users WHERE reset_token_hash IS NOT NULL').get().n, 0, 'no token minted for an unauthorized caller');
    r = await req('POST', '/platform/reset-link', { username: 'nobody-here' }, platformJar);
    assert.strictEqual(r.status, 302, 'unknown username refused');
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM users WHERE reset_token_hash IS NOT NULL').get().n, 0, 'no token minted for unknown accounts');
    r = await req('POST', '/platform/reset-link', { username: 'chair' }, platformJar);
    const resetMatch = r.text.match(/\/reset-password\?token=([0-9a-f]{32})/);
    assert.ok(resetMatch, 'one-time reset link displayed exactly once');
    assert.ok(r.text.includes('Buckeye Fire Fighters Local 100'), 'reset-link page names the account\u2019s local');
    const resetToken = resetMatch[1];
    assert.ok(!db.serialize().toString('latin1').includes(resetToken), 'reset token stored only as a hash');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='platform.reset_link_generated' AND local_id=?").get(localA.id).n >= 1, 'reset-link generation is audited on the account\u2019s local chain');
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM audit_log WHERE detail LIKE ?').get(`%${resetToken}%`).n, 0, 'token plaintext never appears in the audit log');

    r = await req('GET', `/reset-password?token=${resetToken}`, null, null);
    assert.strictEqual(r.status, 200);
    assert.ok(r.text.includes('chair'), 'reset page names the account being reset');
    r = await req('POST', '/reset-password', { token: resetToken, password: 'short', password_confirm: 'short' }, null);
    assert.ok(r.status === 302 && r.location.includes('/reset-password'), 'short password rejected, token still live');
    r = await req('POST', '/reset-password', { token: resetToken, password: 'new-committee-pass-9', password_confirm: 'different-pass-9' }, null);
    assert.ok(r.status === 302 && r.location.includes('/reset-password'), 'mismatched confirmation rejected, token still live');
    r = await req('POST', '/reset-password', { token: resetToken, password: 'new-committee-pass-9', password_confirm: 'new-committee-pass-9' }, null);
    assert.strictEqual(r.location, '/login', 'successful reset lands on sign-in');
    assert.strictEqual(db.prepare('SELECT reset_token_hash FROM users WHERE id=?').get(chairId).reset_token_hash, null, 'token consumed on success');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='auth.password_reset_completed'").get().n >= 1, 'reset completion is audited');
    r = await req('GET', `/reset-password?token=${resetToken}`, null, null);
    assert.strictEqual(r.status, 400, 'used reset token rejected');
    r = await req('POST', '/login', { username: 'chair', password: 'committee-pass-1' }, chairJar);
    assert.strictEqual(r.location, '/login', 'old password no longer works');
    r = await req('POST', '/login', { username: 'chair', password: 'new-committee-pass-9' }, chairJar);
    assert.strictEqual(r.location, '/admin', 'new password signs in');

    /* 20. DEMO / TEST skip-email-verify — election-level, never a global env.
     * Binding still blocks unverified; TEST+demo allows unverified
     * syntactically-valid emails; a TEST with the flag off stays gated;
     * binding FL PERC ratification is still blocked. */
    const dryRun = {
      race_title: 'Practice question', race_seats: '1',
      race_threshold: 'majority', race_candidates: 'Yes\nNo',
      key_shares_total: '3', key_threshold: '2', keyholders: '',
    };
    assert.strictEqual(db.prepare('SELECT demo_skip_email_verify FROM elections WHERE id=?').get(eid).demo_skip_email_verify, 0,
      'binding officer election never stored demo_skip_email_verify');
    r = await req('GET', `/admin/elections/${eid}`, null, chairJar);
    assert.ok(!r.text.includes('DEMO / TEST'),
      'binding election detail does not show the DEMO / TEST banner');
    await req('POST', `/admin/elections/${eid}/demo-skip-email-verify`, { demo_skip_email_verify: '1' }, chairJar);
    assert.strictEqual(db.prepare('SELECT demo_skip_email_verify FROM elections WHERE id=?').get(eid).demo_skip_email_verify, 0,
      'toggle refused on a binding election');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.demo_skip_blocked'").get().n >= 1,
      'refused binding demo-skip toggle is audited');

    r = await req('GET', '/admin/elections/new', null, chairJar);
    assert.ok(r.text.includes('DEMO / TEST dry-run'), 'create form explains TEST skip-email-verify');
    assert.ok(r.text.includes('not a binding election'), 'create form says TEST is not binding');

    /* Binding create that tries to post the bypass still stores 0. */
    await req('POST', '/admin/elections/new', { ...dryRun, title: 'Binding cannot skip verify', kind: 'other', jurisdiction: 'OH', demo_skip_email_verify: '1' }, chairJar);
    const bindNoSkip = db.prepare("SELECT * FROM elections WHERE title=?").get('Binding cannot skip verify');
    assert.ok(bindNoSkip, 'binding other-kind election created');
    assert.strictEqual(bindNoSkip.is_test, 0);
    assert.strictEqual(bindNoSkip.demo_skip_email_verify, 0, 'posted demo_skip on a binding create is ignored');

    /* Reset verification so the remaining gates run against unverified emails. */
    db.prepare("UPDATE members SET email_verified=0 WHERE email IS NOT NULL AND email!=''").run();
    assert.ok(db.prepare("SELECT COUNT(*) n FROM members WHERE email IS NOT NULL AND email!='' AND email_verified=0").get().n >= 6,
      'electronic-path members are unverified for the DEMO dry-run checks');

    /* Binding still blocks unverified after the reset. */
    r = await req('POST', `/admin/elections/${bindNoSkip.id}/issue-credentials`, {}, chairJar);
    assert.strictEqual(db.prepare('SELECT status FROM elections WHERE id=?').get(bindNoSkip.id).status, 'draft',
      'binding still blocks unverified emails for credentials');
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM credentials WHERE election_id=?').get(bindNoSkip.id).n, 0,
      'binding issued no credentials to unverified members');

    /* New TEST election defaults the bypass ON and issues to unverified, syntax-valid emails. */
    await req('POST', '/admin/elections/new', { ...dryRun, title: 'DEMO dry-run vote', kind: 'other', jurisdiction: 'OH', is_test: '1' }, chairJar);
    const demoEid = db.prepare("SELECT * FROM elections WHERE title=?").get('DEMO dry-run vote');
    assert.strictEqual(demoEid.is_test, 1);
    assert.strictEqual(demoEid.demo_skip_email_verify, 1, 'new TEST election defaults demo_skip_email_verify ON');
    r = await req('GET', `/admin/elections/${demoEid.id}`, null, chairJar);
    assert.ok(r.text.includes('DEMO / TEST'), 'TEST election page shows DEMO / TEST banner');
    assert.ok(r.text.includes('not a binding election'), 'TEST banner says not a binding election');
    assert.ok(r.text.includes('Skip email verification is ON') || r.text.includes('skip email verification is on'),
      'election detail shows the DEMO skip toggle state');
    r = await req('POST', `/admin/elections/${demoEid.id}/issue-credentials`, {}, chairJar);
    const demoCreds = [...r.text.matchAll(/[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}/g)].map((m) => m[0]);
    assert.ok(demoCreds.length >= 6, 'TEST+demo issued electronic credentials to unverified syntactically-valid emails');
    assert.strictEqual(db.prepare('SELECT status FROM elections WHERE id=?').get(demoEid.id).status, 'credentials_issued',
      'TEST+demo credential issuance succeeded');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.credentials_issued' AND detail LIKE '%DEMO skip-email-verify ON%'").get().n >= 1,
      'TEST+demo credential issuance is audited as a dry-run');

    /* Existing TEST election can flip the flag off (audit-logged) and then the gate returns. */
    await req('POST', '/admin/elections/new', { ...dryRun, title: 'TEST verify still required', kind: 'other', jurisdiction: 'OH', is_test: '1' }, chairJar);
    const demoOff = db.prepare("SELECT * FROM elections WHERE title=?").get('TEST verify still required');
    assert.strictEqual(demoOff.demo_skip_email_verify, 1, 'second TEST also defaults skip ON');
    await req('POST', `/admin/elections/${demoOff.id}/demo-skip-email-verify`, { demo_skip_email_verify: '0' }, chairJar);
    assert.strictEqual(db.prepare('SELECT demo_skip_email_verify FROM elections WHERE id=?').get(demoOff.id).demo_skip_email_verify, 0,
      'admin toggle turns demo_skip off on a TEST election');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.demo_skip_email_verify'").get().n >= 1,
      'TEST demo-skip toggle is audited');
    r = await req('POST', `/admin/elections/${demoOff.id}/issue-credentials`, {}, chairJar);
    assert.strictEqual(db.prepare('SELECT status FROM elections WHERE id=?').get(demoOff.id).status, 'draft',
      'TEST with demo_skip OFF still blocks unverified emails');
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM credentials WHERE election_id=?').get(demoOff.id).n, 0,
      'TEST with demo_skip OFF issued no credentials');

    /* PERC FL binding ratification is still a hard stop (unchanged by DEMO). */
    const nPerc = electionCount();
    await req('POST', '/admin/elections/new', { ...baseVote, title: 'FL TA Ratification (still blocked)', kind: 'contract_ratification', jurisdiction: 'FL' }, chairJar);
    assert.strictEqual(electionCount(), nPerc, 'PERC FL binding ratification still blocked without variance ack');

    /* ================================================================
     * 21. MULTI-LOCAL ISOLATION — create Local B via the platform flow,
     * give it its own roster and election, and prove Local A and Local B
     * are walled off from each other at the query layer.
     * ================================================================ */
    await req('POST', '/platform/locals', {
      name: 'Prairie Fire Fighters Local 200', local_number: '200', jurisdiction: 'IL',
      admin_display_name: 'Bee Chair', admin_username: 'bee', admin_password: 'committee-pass-2', admin_email: 'bee@example.org',
    }, platformJar);
    const localB = db.prepare("SELECT * FROM locals WHERE name='Prairie Fire Fighters Local 200'").get();
    assert.ok(localB, 'Local B created');
    assert.strictEqual(db.prepare("SELECT local_id FROM users WHERE username='bee'").get().local_id, localB.id, 'Local B\u2019s first account belongs to Local B');

    /* Reusing an existing username across locals must fail cleanly. */
    const localsBefore = db.prepare('SELECT COUNT(*) n FROM locals').get().n;
    await req('POST', '/platform/locals', {
      name: 'Duplicate Username Local', jurisdiction: 'OH',
      admin_display_name: 'X', admin_username: 'chair', admin_password: 'committee-pass-3',
    }, platformJar);
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM locals').get().n, localsBefore, 'duplicate username creates no local (transaction rolled back)');

    r = await req('POST', '/login', { username: 'bee', password: 'committee-pass-2' }, beeJar);
    assert.strictEqual(r.location, '/admin', 'Local B committee signs in');

    /* B starts EMPTY despite all of A's data existing on the instance. */
    r = await req('GET', '/admin', null, beeJar);
    assert.ok(r.text.includes('Prairie Fire Fighters Local 200'), 'B\u2019s pages name B\u2019s local in the header');
    assert.ok(!r.text.includes('2026 Officer Election'), 'B\u2019s dashboard lists none of A\u2019s elections');
    assert.ok(r.text.includes('Roster: 0 members'), 'B\u2019s roster starts empty');
    r = await req('GET', '/admin/members', null, beeJar);
    assert.ok(!r.text.includes('Alice A') && !r.text.includes('a@x.test'), 'B\u2019s roster page shows none of A\u2019s members');
    r = await req('GET', '/admin/users', null, beeJar);
    assert.ok(!r.text.includes('chair') && !r.text.includes('obs1'), 'B\u2019s accounts page shows none of A\u2019s accounts');

    /* B imports its own roster; A's roster is untouched. */
    const aMembersBefore = db.prepare('SELECT COUNT(*) n FROM members WHERE local_id=?').get(localA.id).n;
    await req('POST', '/admin/members/import', { roster: 'Zed Z, z@y.test, 1\nYara Y, y@y.test, 2' }, beeJar);
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM members WHERE local_id=?').get(localB.id).n, 2, 'B imported two members');
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM members WHERE local_id=?').get(localA.id).n, aMembersBefore, 'A\u2019s roster count unchanged by B\u2019s import');

    /* THE ORIGINAL CROSS-LOCAL BUG, dead: B's TEST election (demo skip, so
     * unverified syntax-valid emails qualify) must issue credentials to B's
     * TWO members only — A has ~9 unverified syntax-valid electronic members
     * on the same instance who would all have been swept in when the roster
     * was instance-global. */
    await req('POST', '/admin/elections/new', {
      title: 'Local 200 Practice Vote', kind: 'other', jurisdiction: 'IL', is_test: '1',
      race_title: 'Practice question', race_seats: '1', race_threshold: 'majority', race_candidates: 'Aye\nNay',
      key_shares_total: '3', key_threshold: '2', keyholders: '',
    }, beeJar);
    const beid = db.prepare("SELECT id FROM elections WHERE title='Local 200 Practice Vote'").get().id;
    assert.strictEqual(db.prepare('SELECT local_id FROM elections WHERE id=?').get(beid).local_id, localB.id, 'B\u2019s election belongs to Local B');
    r = await req('POST', `/admin/elections/${beid}/issue-credentials`, {}, beeJar);
    const bCreds = [...r.text.matchAll(/[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}/g)].map((m) => m[0]);
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM credentials WHERE election_id=?').get(beid).n, 2,
      'REGRESSION: B\u2019s issuance created credentials for B\u2019s 2 members ONLY — no stray members from another local');
    assert.strictEqual(bCreds.length, 2, 'exactly two credentials displayed');
    const bSnapshot = JSON.parse(db.prepare('SELECT eligibility_snapshot FROM elections WHERE id=?').get(beid).eligibility_snapshot);
    const bMemberIds = new Set(db.prepare('SELECT id FROM members WHERE local_id=?').all(localB.id).map((m) => m.id));
    assert.ok(bSnapshot.every((s) => bMemberIds.has(s.member_id)), 'B\u2019s eligibility snapshot contains only B\u2019s member ids');
    assert.ok(!r.text.includes('Alice A') && !r.text.includes('Hank H') && !r.text.includes('Gus G'), 'B\u2019s issuance screen names none of A\u2019s members');

    /* B's committee tries to reach A's election by every route: reads,
     * writes, exports. All must behave as if the id does not exist, and A's
     * state must be bit-for-bit unchanged. */
    const aElectionBefore = db.prepare('SELECT * FROM elections WHERE id=?').get(eid);
    r = await req('GET', `/admin/elections/${eid}`, null, beeJar);
    assert.strictEqual(r.status, 404, 'B cannot view A\u2019s election (renders as not found)');
    r = await req('POST', `/admin/elections/${eid}/open`, {}, beeJar);
    assert.strictEqual(r.status, 404, 'B cannot open A\u2019s election');
    r = await req('POST', `/admin/elections/${eid}/close`, {}, beeJar);
    assert.strictEqual(r.status, 404, 'B cannot close A\u2019s election');
    r = await req('POST', `/admin/elections/${eid}/issue-credentials`, {}, beeJar);
    assert.strictEqual(r.status, 404, 'B cannot issue credentials on A\u2019s election');
    r = await req('POST', `/admin/elections/${eid}/tally`, { share: ['SHARE-1-00'] }, beeJar);
    assert.strictEqual(r.status, 404, 'B cannot tally A\u2019s election');
    r = await req('GET', `/admin/elections/${eid}/archive`, null, beeJar);
    assert.strictEqual(r.status, 404, 'B cannot export A\u2019s records archive');
    r = await req('POST', `/admin/elections/${eid}/reissue`, { member_id: '1' }, beeJar);
    assert.strictEqual(r.status, 404, 'B cannot reissue credentials on A\u2019s election');
    r = await req('POST', `/admin/elections/${eid}/demo-skip-email-verify`, { demo_skip_email_verify: '1' }, beeJar);
    assert.strictEqual(r.status, 404, 'B cannot toggle A\u2019s election flags');
    r = await req('POST', `/admin/elections/${eid}/purge-reissue-map`, {}, beeJar);
    assert.strictEqual(r.status, 404, 'B cannot purge A\u2019s reissue map');
    assert.deepStrictEqual(db.prepare('SELECT * FROM elections WHERE id=?').get(eid), aElectionBefore, 'A\u2019s election row is bit-for-bit unchanged after B\u2019s attempts');

    /* B against A's roster rows. */
    const aliceBefore = db.prepare('SELECT * FROM members WHERE id=?').get(alice.id);
    r = await req('POST', `/admin/members/${alice.id}/update`, { email: 'hijack@evil.test', good_standing: '0', needs_paper_ballot: '1' }, beeJar);
    assert.strictEqual(r.status, 302, 'B\u2019s edit of A\u2019s member bounces');
    r = await req('POST', `/admin/members/${alice.id}/send-verification`, {}, beeJar);
    assert.strictEqual(r.status, 302, 'B cannot mint verification links for A\u2019s member');
    assert.deepStrictEqual(db.prepare('SELECT * FROM members WHERE id=?').get(alice.id), aliceBefore, 'A\u2019s member row is unchanged after B\u2019s attempts');

    /* B against A's accounts. */
    const obs1Before = db.prepare("SELECT * FROM users WHERE username='obs1'").get();
    r = await req('POST', `/admin/users/${obs1Before.id}/email`, { email: 'stolen@evil.test' }, beeJar);
    assert.deepStrictEqual(db.prepare("SELECT * FROM users WHERE username='obs1'").get(), obs1Before, 'B cannot touch A\u2019s accounts');

    /* B cannot pull A's member onto B's own turnout list. */
    await req('POST', `/admin/elections/${beid}/open`, {}, beeJar);
    r = await req('POST', `/admin/elections/${beid}/paper-received`, { member_id: String(alice.id) }, beeJar);
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM turnout WHERE election_id=? AND member_id=?').get(beid, alice.id).n, 0,
      'A\u2019s member cannot be marked as voted in B\u2019s election');

    /* The mirror direction: A's committee cannot reach B's election. */
    r = await req('GET', `/admin/elections/${beid}`, null, chairJar);
    assert.strictEqual(r.status, 404, 'A cannot view B\u2019s election either');

    /* Voter isolation: a B credential opens exactly B's ballot. */
    r = await req('POST', '/vote', { credential: bCreds[0] }, null);
    assert.ok(r.text.includes('Local 200 Practice Vote'), 'B\u2019s credential opens B\u2019s ballot');
    assert.ok(!r.text.includes('2026 Officer Election'), 'and no other local\u2019s election');

    /* B's observer sees only B; B's audit chain carries none of A's PII. */
    await req('POST', '/admin/users', { display_name: 'B Observer', username: 'obs200', password: 'observer-pass-2', role: 'observer' }, beeJar);
    r = await req('POST', '/login', { username: 'obs200', password: 'observer-pass-2' }, obsBJar);
    assert.strictEqual(r.location, '/observe', 'B\u2019s observer signs in');
    r = await req('GET', '/observe', null, obsBJar);
    assert.ok(r.text.includes('Local 200 Practice Vote'), 'B\u2019s observer sees B\u2019s election');
    assert.ok(!r.text.includes('2026 Officer Election'), 'B\u2019s observer sees none of A\u2019s elections');
    r = await req('GET', `/observe/elections/${eid}`, null, obsBJar);
    assert.strictEqual(r.status, 302, 'B\u2019s observer is bounced off A\u2019s election page');
    r = await req('GET', '/observe/audit', null, obsBJar);
    assert.ok(r.text.includes('Local 200 Practice Vote'), 'B\u2019s audit page shows B\u2019s own events');
    for (const aPii of ['Alice', 'Bob B', 'Hank H', 'a@x.test', '2026 Officer Election']) {
      assert.ok(!r.text.includes(aPii), `B\u2019s audit page never shows A\u2019s data (${aPii})`);
    }
    assert.ok(r.text.includes('intact'), 'B\u2019s chain verifies on its own');

    /* A's audit page conversely carries none of B's roster. */
    r = await req('GET', '/observe/audit', null, chairJar);
    assert.ok(!r.text.includes('Zed Z') && !r.text.includes('z@y.test'), 'A\u2019s audit page never shows B\u2019s members');

    /* Per-local chains and the platform chain all verify independently. */
    assert.ok(verifyAuditChain(localA.id).ok, 'Local A chain verifies');
    assert.ok(verifyAuditChain(localB.id).ok, 'Local B chain verifies');
    assert.ok(verifyAuditChain(null).ok, 'platform chain verifies');
    assert.ok(db.prepare('SELECT COUNT(*) n FROM audit_log WHERE local_id IS NOT NULL AND local_id NOT IN (SELECT id FROM locals)').get().n === 0,
      'no audit entry points at a nonexistent local');

    /* All-locals rollup still contains no PII from either local, and the
     * per-local breakdown carries both locals' counts. */
    r = await req('GET', '/platform', null, platformJar);
    assert.ok(r.text.includes('Prairie Fire Fighters Local 200') && r.text.includes('Buckeye Fire Fighters Local 100'), 'per-local stats list both locals');
    for (const pii of ['Alice', 'Bob B', 'a@x.test', 'Hank H', 'hank@example.org', 'chair@', 'Zed Z', 'Yara Y', 'z@y.test', 'bee@example.org']) {
      assert.ok(!r.text.includes(pii), `platform rollup never shows PII (${pii})`);
    }

    /* Legacy /setup now just signposts to /login on a configured instance. */
    r = await req('GET', '/setup', null, null);
    assert.ok(r.status === 302 && r.location === '/login', 'legacy /setup redirects to sign-in once the platform is configured');

    /* ================================================================
     * 22. MIGRATION — a database created BEFORE multi-tenancy (no locals, no
     * local_id columns, one instance-wide audit chain, real rows) must boot,
     * create ONE default local named from the data, assign every existing
     * row to it, keep the old committee login working, and leave nothing
     * orphaned. Runs in a child process against its own DATA_DIR.
     * ================================================================ */
    fs.mkdirSync(MIGRATE_DIR, { recursive: true });
    const oldDb = new Database(path.join(MIGRATE_DIR, 'ballot.db'));
    oldDb.exec(`
      CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE users (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin','observer')), display_name TEXT NOT NULL,
        email TEXT, reset_token_hash TEXT, reset_token_sent_at TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE members (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT, member_number TEXT,
        good_standing INTEGER NOT NULL DEFAULT 1, needs_paper_ballot INTEGER NOT NULL DEFAULT 0,
        email_verified INTEGER NOT NULL DEFAULT 0, email_verified_at TEXT,
        email_verify_token_hash TEXT, email_verify_sent_at TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE elections (
        id INTEGER PRIMARY KEY, title TEXT NOT NULL, kind TEXT NOT NULL, jurisdiction TEXT,
        perc_variance_ack INTEGER NOT NULL DEFAULT 0, perc_variance_ref TEXT, iaff_legal_approval TEXT,
        is_test INTEGER NOT NULL DEFAULT 0, demo_skip_email_verify INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'draft', notice_sent_on TEXT, opens_at TEXT, closes_at TEXT,
        public_key TEXT, key_shares_total INTEGER, key_threshold INTEGER, keyholders TEXT,
        eligibility_snapshot TEXT, results_json TEXT, tallied_at TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE races (id INTEGER PRIMARY KEY, election_id INTEGER NOT NULL, title TEXT NOT NULL, seats INTEGER NOT NULL DEFAULT 1, threshold TEXT NOT NULL DEFAULT 'majority', position INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE candidates (id INTEGER PRIMARY KEY, race_id INTEGER NOT NULL, name TEXT NOT NULL, position INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE credentials (id INTEGER PRIMARY KEY, election_id INTEGER NOT NULL, code_hash TEXT NOT NULL, salt TEXT NOT NULL, member_ref TEXT NOT NULL, voided INTEGER NOT NULL DEFAULT 0, redeemed INTEGER NOT NULL DEFAULT 0, redeemed_on TEXT);
      CREATE TABLE turnout (election_id INTEGER NOT NULL, member_id INTEGER NOT NULL, voted_on TEXT NOT NULL, method TEXT NOT NULL DEFAULT 'electronic', PRIMARY KEY (election_id, member_id));
      CREATE TABLE ballots (id TEXT PRIMARY KEY, election_id INTEGER NOT NULL, payload TEXT NOT NULL) WITHOUT ROWID;
      CREATE TABLE audit_log (id INTEGER PRIMARY KEY, at TEXT NOT NULL DEFAULT (datetime('now')), actor TEXT NOT NULL, event TEXT NOT NULL, detail TEXT, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
      CREATE TABLE archives (id INTEGER PRIMARY KEY, election_id INTEGER NOT NULL, election_title TEXT NOT NULL, tallied_at TEXT, ballot_count INTEGER NOT NULL DEFAULT 0, filename TEXT NOT NULL, encrypted INTEGER NOT NULL DEFAULT 0, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now')));
    `);
    oldDb.prepare('INSERT INTO users (username, password_hash, role, display_name) VALUES (?,?,?,?)')
      .run('oldchair', bcrypt.hashSync('legacy-pass-123456', 12), 'admin', 'Legacy Chair');
    oldDb.prepare('INSERT INTO members (name, email, member_number, email_verified) VALUES (?,?,?,1)').run('Pat P', 'p@old.test', '11');
    oldDb.prepare('INSERT INTO members (name, email, member_number) VALUES (?,NULL,?)').run('Quinn Q', '12');
    oldDb.prepare(`INSERT INTO elections (title, kind, jurisdiction, iaff_legal_approval, status, eligibility_snapshot, results_json, tallied_at)
      VALUES (?,?,?,?,?,?,?,datetime('now'))`)
      .run('Local 947 Officer Election 2025', 'officer_election', 'NC', 'IAFF letter 2025-01-01', 'tallied',
        JSON.stringify([{ member_id: 1, method: 'electronic' }, { member_id: 2, method: 'paper' }]),
        JSON.stringify({ races: [], ballots_cast: 1, integrity_ok: true }));
    oldDb.prepare('INSERT INTO races (election_id, title) VALUES (1, ?)').run('President');
    oldDb.prepare('INSERT INTO candidates (race_id, name) VALUES (1, ?)').run('Old Candidate');
    oldDb.prepare("INSERT INTO credentials (election_id, code_hash, salt, member_ref, redeemed, redeemed_on) VALUES (1,'h','s','',1,date('now'))").run();
    oldDb.prepare("INSERT INTO turnout (election_id, member_id, voted_on) VALUES (1,1,date('now'))").run();
    oldDb.prepare("INSERT INTO ballots (id, election_id, payload) VALUES (?,1,'ciphertext')").run(crypto.randomUUID());
    oldDb.prepare("INSERT INTO archives (election_id, election_title, ballot_count, filename, sha256) VALUES (1,'Local 947 Officer Election 2025',1,'election-1-records.json','deadbeef')").run();
    /* A real pre-migration audit chain (the old single-chain format). */
    const GENESIS = '0'.repeat(64);
    const chainHash = (prev, json) => crypto.createHash('sha256').update(prev + '|' + json).digest('hex');
    let prevHash = GENESIS;
    for (const [actor, event, detail] of [
      ['system', 'setup.admin_created', 'Election-committee admin account "oldchair" created'],
      ['oldchair', 'election.created', 'Election #1 "Local 947 Officer Election 2025" created'],
      ['oldchair', 'tally.completed', 'Election #1: 1 ballots counted'],
    ]) {
      const entryHash = chainHash(prevHash, JSON.stringify({ actor, event, detail }));
      oldDb.prepare('INSERT INTO audit_log (actor, event, detail, prev_hash, entry_hash) VALUES (?,?,?,?,?)')
        .run(actor, event, detail, prevHash, entryHash);
      prevHash = entryHash;
    }
    oldDb.close();

    /* Child script: boot the app on the old database (migrations run at
     * startup), sign in with the LEGACY credentials, load the dashboard and
     * roster, verify chains with production code, and report as JSON. */
    const childScript = path.join(MIGRATE_DIR, 'migration-check.js');
    fs.writeFileSync(childScript, `
      'use strict';
      process.env.DATA_DIR = ${JSON.stringify(MIGRATE_DIR)};
      process.env.PORT = '4001';
      delete process.env.BRAND_LOCAL; delete process.env.BRAND_ORG;
      const app = require(${JSON.stringify(path.join(__dirname, '..', 'server.js'))});
      const { db, verifyAuditChain } = require(${JSON.stringify(path.join(__dirname, '..', 'src', 'db.js'))});
      (async () => {
        const server = app.listen(4001);
        try {
          const out = {};
          const login = await fetch('http://localhost:4001/login', {
            method: 'POST', redirect: 'manual',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ username: 'oldchair', password: 'legacy-pass-123456' }).toString(),
          });
          out.loginLocation = login.headers.get('location');
          const cookie = (login.headers.get('set-cookie') || '').split(';')[0];
          const dash = await fetch('http://localhost:4001/admin', { headers: { Cookie: cookie } });
          const dashText = await dash.text();
          out.dashboardHasElection = dashText.includes('Local 947 Officer Election 2025');
          out.dashboardNamesLocal = dashText.includes('Local 947');
          const roster = await fetch('http://localhost:4001/admin/members', { headers: { Cookie: cookie } });
          const rosterText = await roster.text();
          out.rosterHasMember = rosterText.includes('Pat P');
          out.local = db.prepare('SELECT * FROM locals ORDER BY id LIMIT 1').get() || null;
          out.localCount = db.prepare('SELECT COUNT(*) n FROM locals').get().n;
          out.defaultLocalSetting = (db.prepare("SELECT value FROM settings WHERE key='default_local_id'").get() || {}).value || null;
          out.orphans = {};
          for (const t of ['members', 'elections', 'users', 'archives']) {
            out.orphans[t] = db.prepare('SELECT COUNT(*) n FROM ' + t + ' WHERE local_id IS NULL').get().n;
          }
          out.auditNullEvents = db.prepare('SELECT event FROM audit_log WHERE local_id IS NULL ORDER BY id').all().map((r) => r.event);
          out.rowsInDefaultLocal = {
            members: db.prepare('SELECT COUNT(*) n FROM members WHERE local_id=?').get(out.local.id).n,
            elections: db.prepare('SELECT COUNT(*) n FROM elections WHERE local_id=?').get(out.local.id).n,
            users: db.prepare('SELECT COUNT(*) n FROM users WHERE local_id=?').get(out.local.id).n,
            archives: db.prepare('SELECT COUNT(*) n FROM archives WHERE local_id=?').get(out.local.id).n,
            audit: db.prepare('SELECT COUNT(*) n FROM audit_log WHERE local_id=?').get(out.local.id).n,
          };
          out.migratedEventCount = db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='platform.migrated_to_locals'").get().n;
          out.chainLocal = verifyAuditChain(out.local.id);
          out.chainPlatform = verifyAuditChain(null);
          console.log('RESULT:' + JSON.stringify(out));
        } finally { server.close(); }
      })().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
    `);
    const runMigrationCheck = () => {
      const stdout = execFileSync(process.execPath, [childScript], {
        env: { ...process.env, DATA_DIR: MIGRATE_DIR, PORT: '4001' },
        encoding: 'utf8',
      });
      const line = stdout.split('\n').find((l) => l.startsWith('RESULT:'));
      assert.ok(line, 'migration child reported a result');
      return JSON.parse(line.slice('RESULT:'.length));
    };

    const mig = runMigrationCheck();
    assert.strictEqual(mig.localCount, 1, 'migration created exactly one default local');
    assert.strictEqual(mig.local.name, 'Local 947', 'default local named from the real "Local NNN" pattern in existing election titles — not a placeholder');
    assert.strictEqual(mig.local.local_number, '947', 'local number extracted from the data');
    assert.strictEqual(mig.local.jurisdiction, 'NC', 'jurisdiction inferred from the existing election');
    assert.strictEqual(Number(mig.defaultLocalSetting), mig.local.id, 'default local id remembered in settings');
    assert.deepStrictEqual(mig.orphans, { members: 0, elections: 0, users: 0, archives: 0 }, 'NOTHING orphaned: every pre-existing row was assigned to the default local');
    assert.deepStrictEqual(mig.rowsInDefaultLocal, { members: 2, elections: 1, users: 1, archives: 1, audit: 4 },
      'all pre-existing rows (and the new login event) belong to the default local');
    assert.ok(mig.auditNullEvents.includes('platform.migrated_to_locals'), 'the migration itself is audited on the platform chain');
    assert.ok(mig.chainLocal.ok && mig.chainLocal.total >= 3, 'the old instance-wide audit chain still verifies, untouched, as the default local\u2019s chain');
    assert.ok(mig.chainPlatform.ok, 'the new platform chain verifies');
    assert.strictEqual(mig.loginLocation, '/admin', 'the pre-migration committee login still works unchanged');
    assert.ok(mig.dashboardHasElection, 'the migrated committee still sees its election');
    assert.ok(mig.dashboardNamesLocal, 'migrated pages name the default local in the header');
    assert.ok(mig.rosterHasMember, 'the migrated committee still sees its roster');

    /* Idempotency: booting the migrated database again must not create a
     * second local or re-run the backfill. */
    const mig2 = runMigrationCheck();
    assert.strictEqual(mig2.localCount, 1, 'second boot creates no second local');
    assert.strictEqual(mig2.migratedEventCount, 1, 'backfill ran exactly once');
    assert.ok(mig2.chainLocal.ok && mig2.chainPlatform.ok, 'chains still verify after a second boot');

    console.log('\nALL SMOKE TESTS PASSED ✔');
    console.log(`  Local A election #${eid}: 6 ballots, Smith elected (majority), dues adopted (2/3).`);
    console.log('  Verified: approval gate, one-time shares, hashed credentials, unlinkable ballots,');
    console.log('  date-only redemption, double-vote rejection, 3-of-5 threshold tally, per-local audit chain, archive.');
    console.log('  Verified: email-verification gate (block/verify/single-use token/reset-on-change),');
    console.log('  Florida PERC ratification hard stop (block, variance path, test/non-ratification/non-FL unaffected),');
    console.log('  roster-import email-syntax gate (bad rows reported with reasons, good rows imported,');
    console.log('  blank email = paper path untouched, member-edit rejects malformed addresses).');
    console.log('  Verified: automatic sealed archive at tally (encrypted under BACKUP_KEY, no shares, no credential');
    console.log('  plaintext, local-scoped audit log), platform bootstrap gated by PLATFORM_OWNER_KEY, platform');
    console.log('  accounts (bcrypt, own sign-in; committee sessions refused), per-local stats + all-locals rollup');
    console.log('  with zero PII, archive + whole-DB backup moved to the platform role, and password recovery');
    console.log('  (hash-only single-use expiring tokens, platform one-time link naming the local, old password dies).');
    console.log('  Verified: DEMO/TEST skip-email-verify is election-scoped (new TEST defaults ON, binding can never');
    console.log('  set or honor it, toggle is audited, unverified syntax-valid emails get credentials only on TEST+demo,');
    console.log('  PERC FL binding still blocked).');
    console.log('  Verified: MULTI-LOCAL ISOLATION — Local B\u2019s committee/observer cannot read or write Local A\u2019s');
    console.log('  roster, elections, credentials, accounts, archives, or audit chain by any route or guessed id');
    console.log('  (and vice versa); credential issuance sweeps in ONLY the owning local\u2019s roster (the cross-local');
    console.log('  bug regression test); per-local + platform hash chains verify independently.');
    console.log('  Verified: MIGRATION — a pre-multi-tenant database boots, everything lands in one default local');
    console.log('  named from the real data ("Local 947", NC), the legacy committee login keeps working, the old');
    console.log('  audit chain verifies untouched, nothing is orphaned, and the backfill is idempotent.');
  } finally {
    server.close();
    fs.rmSync(process.env.DATA_DIR, { recursive: true, force: true });
    fs.rmSync(MIGRATE_DIR, { recursive: true, force: true });
  }
})().catch((e) => { console.error('SMOKE TEST FAILED:', e); process.exit(1); });
