/**
 * scripts/preview-test.js: Tests for the committee ballot preview.
 *
 * The preview must:
 *  1. Render the EXACT voter ballot view (same template) in every election
 *     status: draft, credentials_issued, open, closed, and tallied; with
 *     radio buttons for 1-seat races and checkboxes for multi-seat races,
 *     a prominent "PREVIEW, NOT A REAL BALLOT" banner, every input
 *     disabled, no credential field, and no enabled Cast button.
 *  2. Make posting impossible: the preview form has no /vote/cast action,
 *     a POST to the preview URL itself is a 404, and nothing reachable
 *     from the preview can cast a ballot.
 *  3. Touch nothing: no credential, ballot, turnout, or election key data
 *     may change when a preview is rendered. Only the audit entry
 *     ("ballot previewed") is written.
 *  4. Honor tenancy and roles: committee and observers of the owning local
 *     can preview; another local's committee gets a 404; anonymous
 *     visitors are sent to sign in.
 */
'use strict';
const crypto = require('crypto');
process.env.DATA_DIR = require('path').join(__dirname, '..', 'data-test-preview');
process.env.PORT = '3997';
process.env.REISSUE_KEY = process.env.REISSUE_KEY || crypto.randomBytes(32).toString('hex');
const PLATFORM_KEY = 'platform-owner-preview-key-0001';
process.env.PLATFORM_OWNER_KEY = PLATFORM_KEY;
const fs = require('fs');
fs.rmSync(process.env.DATA_DIR, { recursive: true, force: true });

const app = require('../server');
const { db } = require('../src/db');
const assert = require('assert');

const BASE = 'http://localhost:3997';

function jar() { return { cookie: '' }; }
const adminJar = jar();     // Local A committee
const beeJar = jar();       // Local B committee (isolation check)
const obsJar = jar();       // Local A observer
const platformJar = jar();

async function req(method, path, body, session = adminJar) {
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
  if (setc && session) session.cookie = setc.split(';')[0];
  return { status: r.status, text: await r.text(), location: r.headers.get('location') };
}

(async () => {
  const server = app.listen(3997);
  try {
    /* ---------------- bootstrap: platform, Local A, committee ------------ */
    await req('POST', '/platform/setup', { key: PLATFORM_KEY, username: 'operator', password: 'platform-pass-01', display_name: 'Operator' }, platformJar);
    await req('POST', '/platform/auth', { username: 'operator', password: 'platform-pass-01' }, platformJar);
    await req('POST', '/platform/locals', {
      name: 'Preview Fire Fighters Local 400', local_number: '400', jurisdiction: 'OH',
      admin_display_name: 'Chair', admin_username: 'chair400', admin_password: 'committee-pass-1',
    }, platformJar);
    let r = await req('POST', '/login', { username: 'chair400', password: 'committee-pass-1' }, adminJar);
    assert.strictEqual(r.location, '/admin', 'committee signed in');

    await req('POST', '/admin/members/import', {
      roster: ['Pat P, pat@p.test, 1', 'Quinn Q, quinn@p.test, 2', 'Rita R, rita@p.test, 3'].join('\n'),
    }, adminJar);

    /* TEST election (demo skip on) so credentials can be issued without SMTP
     * or magic-link confirms: one 1-seat race, one 2-seat race. */
    r = await req('POST', '/admin/elections/new', {
      title: 'Preview Fixture Election', kind: 'officer_election', jurisdiction: 'OH', is_test: '1',
      race_title: ['President', 'Trustees'],
      race_seats: ['1', '2'],
      race_threshold: ['majority', 'plurality'],
      race_candidates: ['P Alpha\nP Bravo\nP Charlie', 'T Delta\nT Echo\nT Foxtrot'],
      key_shares_total: '3', key_threshold: '2', keyholders: '',
    }, adminJar);
    const shares = [...r.text.matchAll(/SHARE-\d+-[0-9a-f]+/g)].map((m) => m[0]);
    assert.strictEqual(shares.length, 3, 'key shares captured');
    const eid = db.prepare('SELECT id FROM elections ORDER BY id DESC LIMIT 1').get().id;
    const races = db.prepare('SELECT * FROM races WHERE election_id=? ORDER BY position').all(eid);
    const pres = races[0]; const trustees = races[1];
    const previewPath = `/admin/elections/${eid}/preview`;

    /* Everything a preview must never change, serialized for exact compare.
     * (The audit log is excluded: the preview is REQUIRED to append there.) */
    function snapshotRows() {
      return JSON.stringify({
        credentials: db.prepare('SELECT * FROM credentials ORDER BY id').all(),
        ballots: db.prepare('SELECT * FROM ballots ORDER BY id').all(),
        turnout: db.prepare('SELECT * FROM turnout ORDER BY election_id, member_id').all(),
        election: db.prepare('SELECT status, public_key, key_shares_total, key_threshold, keyholders, eligibility_snapshot, results_json FROM elections WHERE id=?').get(eid),
        settings: db.prepare('SELECT * FROM settings ORDER BY key').all(),
      });
    }

    const previewAudits = () => db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.ballot_previewed' AND detail LIKE '%ballot previewed%'").get().n;

    async function assertReadOnlyPreview(label, path, session) {
      const before = snapshotRows();
      const auditsBefore = previewAudits();
      const page = await req('GET', path, null, session);
      assert.strictEqual(page.status, 200, `${label}: preview renders (status 200)`);
      assert.ok(page.text.includes('PREVIEW, NOT A REAL BALLOT'), `${label}: prominent preview banner shown`);
      assert.ok(page.text.includes('Preview Fixture Election'), `${label}: election title shown`);
      /* The exact voter ballot view: race titles, candidates, instructions. */
      for (const t of ['President', 'Trustees', 'P Alpha', 'P Bravo', 'P Charlie', 'T Delta', 'T Echo', 'T Foxtrot', 'Vote for one.', 'Vote for up to 2.']) {
        assert.ok(page.text.includes(t), `${label}: ballot content includes ${JSON.stringify(t)}`);
      }
      /* Radio buttons for the 1-seat race, checkboxes for the 2-seat race. */
      const inputs = page.text.match(/<input[^>]*>/g) || [];
      const presInputs = inputs.filter((i) => i.includes(`name="race_${pres.id}"`));
      const trusteeInputs = inputs.filter((i) => i.includes(`name="race_${trustees.id}"`));
      assert.strictEqual(presInputs.length, 3, `${label}: three inputs for the 1-seat race`);
      assert.ok(presInputs.every((i) => i.includes('type="radio"')), `${label}: 1-seat race uses radio buttons`);
      assert.strictEqual(trusteeInputs.length, 3, `${label}: three inputs for the multi-seat race`);
      assert.ok(trusteeInputs.every((i) => i.includes('type="checkbox"')), `${label}: multi-seat race uses checkboxes`);
      /* Read-only: every input disabled, no credential field, no live form
       * target, no enabled Cast button. */
      assert.ok(inputs.length > 0 && inputs.every((i) => i.includes('disabled')), `${label}: every input is disabled`);
      assert.ok(!page.text.includes('name="credential"'), `${label}: no credential field is rendered`);
      assert.ok(!page.text.includes('action="/vote/cast"'), `${label}: the form does not post to /vote/cast`);
      const formMatch = page.text.match(/<form[^>]*id="ballotForm"[\s\S]*?<\/form>/);
      assert.ok(formMatch, `${label}: ballot form present`);
      assert.ok(!formMatch[0].includes('type="submit"'), `${label}: no submit button inside the ballot form`);
      assert.ok(/<button[^>]*type="button"[^>]*disabled[^>]*>Cast ballot \(final\)<\/button>/.test(formMatch[0]), `${label}: Cast button is present but disabled`);
      /* Nothing changed; one audit entry added. */
      assert.strictEqual(snapshotRows(), before, `${label}: no credential, ballot, turnout, key, or settings data changed`);
      assert.strictEqual(previewAudits(), auditsBefore + 1, `${label}: "ballot previewed" audit entry written`);
      return page.text;
    }

    const ballotCount = () => db.prepare('SELECT COUNT(*) n FROM ballots WHERE election_id=?').get(eid).n;
    const credCount = () => db.prepare('SELECT COUNT(*) n FROM credentials WHERE election_id=?').get(eid).n;
    const turnoutCount = () => db.prepare('SELECT COUNT(*) n FROM turnout WHERE election_id=?').get(eid).n;

    /* ---------------- 1. DRAFT: preview before credentials exist --------- */
    assert.strictEqual(db.prepare('SELECT status FROM elections WHERE id=?').get(eid).status, 'draft');
    await assertReadOnlyPreview('draft', previewPath, adminJar);
    assert.strictEqual(credCount(), 0, 'draft: still no credentials after preview');

    /* Posting at the preview URL itself must be impossible. */
    r = await req('POST', previewPath, { ['race_' + pres.id]: '1' }, adminJar);
    assert.strictEqual(r.status, 404, 'POST to the preview URL is a 404');
    assert.strictEqual(ballotCount(), 0, 'no ballot landed from a POST to the preview URL');

    /* ---------------- 2. CREDENTIALS_ISSUED ------------------------------ */
    r = await req('POST', `/admin/elections/${eid}/issue-credentials`, {}, adminJar);
    const creds = [...r.text.matchAll(/[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}/g)].map((m) => m[0]);
    assert.strictEqual(creds.length, 3, 'three credentials issued');
    await assertReadOnlyPreview('credentials_issued', previewPath, adminJar);
    assert.strictEqual(credCount(), 3, 'credential rows unchanged by preview');

    /* ---------------- 3. OPEN: preview alongside real voting ------------- */
    await req('POST', `/admin/elections/${eid}/open`, {}, adminJar);
    const presCands = db.prepare('SELECT * FROM candidates WHERE race_id=? ORDER BY position').all(pres.id);
    const trusteeCands = db.prepare('SELECT * FROM candidates WHERE race_id=? ORDER BY position').all(trustees.id);
    r = await req('POST', '/vote/cast', {
      credential: creds[0],
      ['race_' + pres.id]: String(presCands[0].id),
      ['race_' + trustees.id]: [String(trusteeCands[0].id), String(trusteeCands[1].id)],
    }, null);
    assert.ok(r.text.includes('Your ballot was cast'), 'a real ballot casts while open');
    assert.strictEqual(ballotCount(), 1);

    await assertReadOnlyPreview('open', previewPath, adminJar);
    assert.strictEqual(ballotCount(), 1, 'open: ballot count unchanged by preview');
    assert.strictEqual(turnoutCount(), 1, 'open: turnout unchanged by preview');

    /* The real voter ballot (as opposed to the preview) still works: it has
     * the credential field, a live /vote/cast action, and enabled inputs. */
    r = await req('POST', '/vote', { credential: creds[1] }, null);
    assert.strictEqual(r.status, 200, 'a live credential still opens the real ballot');
    assert.ok(!r.text.includes('PREVIEW, NOT A REAL BALLOT'), 'the real ballot carries no preview banner');
    assert.ok(r.text.includes('action="/vote/cast"') && r.text.includes('name="credential"'), 'the real ballot posts to /vote/cast with the credential');
    assert.ok(r.text.includes('type="submit"'), 'the real ballot has an enabled Cast button');
    const realInputs = r.text.match(/<input[^>]*>/g) || [];
    assert.ok(realInputs.every((i) => !i.includes('disabled')), 'real ballot inputs are not disabled');

    /* A cast attempt with no credential (all the preview could ever "know")
     * records nothing. */
    const beforeCast = ballotCount();
    r = await req('POST', '/vote/cast', { credential: '', ['race_' + pres.id]: String(presCands[0].id) }, null);
    assert.strictEqual(r.status, 302, 'credential-less cast bounces');
    assert.strictEqual(ballotCount(), beforeCast, 'no ballot landed without a credential');

    /* ---------------- 4. CLOSED ------------------------------------------ */
    await req('POST', `/admin/elections/${eid}/close`, {}, adminJar);
    await assertReadOnlyPreview('closed', previewPath, adminJar);

    /* ---------------- 5. TALLIED (preview works in ANY status) ----------- */
    await req('POST', `/admin/elections/${eid}/tally`, { share: [shares[0], shares[2]] }, adminJar);
    assert.strictEqual(db.prepare('SELECT status FROM elections WHERE id=?').get(eid).status, 'tallied');
    await assertReadOnlyPreview('tallied', previewPath, adminJar);

    /* ---------------- 6. Observers: read-only preview too ---------------- */
    await req('POST', '/admin/users', { display_name: 'Obs', username: 'obs400', password: 'observer-pass-1', role: 'observer' }, adminJar);
    r = await req('POST', '/login', { username: 'obs400', password: 'observer-pass-1' }, obsJar);
    assert.strictEqual(r.location, '/observe', 'observer signed in');
    r = await req('GET', `/observe/elections/${eid}`, null, obsJar);
    assert.ok(r.text.includes(`/observe/elections/${eid}/preview`), 'observer election page links the preview');
    await assertReadOnlyPreview('observer', `/observe/elections/${eid}/preview`, obsJar);
    r = await req('POST', `/observe/elections/${eid}/preview`, {}, obsJar);
    assert.strictEqual(r.status, 404, 'POST to the observer preview URL is a 404');

    /* Observers cannot reach the committee preview route (role check). */
    r = await req('GET', previewPath, null, obsJar);
    assert.strictEqual(r.status, 403, 'observer is refused the committee preview route');

    /* ---------------- 7. Tenancy and authentication ---------------------- */
    r = await req('GET', previewPath, null, null);
    assert.strictEqual(r.status, 302, 'anonymous preview request is redirected');
    assert.strictEqual(r.location, '/login', 'anonymous preview request lands on sign-in');

    await req('POST', '/platform/locals', {
      name: 'Other Fire Fighters Local 500', local_number: '500', jurisdiction: 'IL',
      admin_display_name: 'Bee', admin_username: 'bee500', admin_password: 'committee-pass-2',
    }, platformJar);
    await req('POST', '/login', { username: 'bee500', password: 'committee-pass-2' }, beeJar);
    const beforeForeign = snapshotRows();
    r = await req('GET', previewPath, null, beeJar);
    assert.strictEqual(r.status, 404, 'another local\u2019s committee cannot preview this ballot (renders as not found)');
    r = await req('GET', `/observe/elections/${eid}/preview`, null, beeJar);
    assert.ok(r.status === 302 || r.status === 404, 'another local\u2019s session is bounced off the observer preview too');
    assert.strictEqual(snapshotRows(), beforeForeign, 'foreign preview attempts changed nothing');

    /* The committee election page always offers the button. */
    r = await req('GET', `/admin/elections/${eid}`, null, adminJar);
    assert.ok(r.text.includes(previewPath), 'election detail page links the ballot preview');
    assert.ok(r.text.includes('Preview ballot'), 'election detail page shows the Preview ballot button');

    console.log('\nALL BALLOT-PREVIEW TESTS PASSED \u2714');
    console.log('  Preview renders the exact voter ballot (radio for 1 seat, checkboxes for multi-seat)');
    console.log('  in draft, credentials_issued, open, closed, and tallied; shows the PREVIEW banner;');
    console.log('  disables every input; exposes no credential and no live form target; POSTs to the');
    console.log('  preview URL are 404s; no credential, ballot, turnout, or key data ever changes;');
    console.log('  each preview is audited; observers get the same read-only view; other locals and');
    console.log('  anonymous visitors are refused.');
  } finally {
    server.close();
    fs.rmSync(process.env.DATA_DIR, { recursive: true, force: true });
  }
})().catch((e) => { console.error('BALLOT-PREVIEW TEST FAILED:', e); process.exit(1); });
