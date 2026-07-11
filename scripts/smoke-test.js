/**
 * scripts/smoke-test.js — Full end-to-end election against the live server.
 * Verifies: setup → roster → create (with IAFF approval gate) → key ceremony →
 * credentials → open → 6 ballots cast → close → tally with 3-of-5 shares →
 * majority/runoff math → anonymity properties of stored data.
 */
'use strict';
process.env.DATA_DIR = require('path').join(__dirname, '..', 'data-test');
process.env.PORT = '3999';
const fs = require('fs');
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

    /* 3. IAFF approval gate: officer election WITHOUT approval must be rejected */
    let r = await req('POST', '/admin/elections/new', {
      title: 'Should Fail', kind: 'officer_election',
      race_title: 'President', race_seats: '1', race_threshold: 'majority', race_candidates: 'X\nY',
      key_shares_total: '5', key_threshold: '3', keyholders: '',
    });
    assert.strictEqual(db.prepare('SELECT COUNT(*) n FROM elections').get().n, 0, 'approval gate blocks unapproved officer election');

    /* 4. Create officer election WITH recorded approval; capture key shares */
    r = await req('POST', '/admin/elections/new', {
      title: '2026 Officer Election', kind: 'officer_election',
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

    console.log('\nALL SMOKE TESTS PASSED ✔');
    console.log(`  Election #${eid}: 6 ballots, Smith elected (majority), dues adopted (2/3).`);
    console.log('  Verified: approval gate, one-time shares, hashed credentials, unlinkable ballots,');
    console.log('  date-only redemption, double-vote rejection, 3-of-5 threshold tally, audit chain, archive.');
  } finally {
    server.close();
    fs.rmSync(process.env.DATA_DIR, { recursive: true, force: true });
  }
})().catch((e) => { console.error('SMOKE TEST FAILED:', e); process.exit(1); });
