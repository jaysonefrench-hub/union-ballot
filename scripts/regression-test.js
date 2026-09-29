/**
 * scripts/regression-test.js: Regression tests for the double-vote and
 * tally fixes. Runs a live server on its own throwaway DATA_DIR, exactly
 * like scripts/smoke-test.js. Covers:
 *
 *  1. Paper + online double vote: recording a paper receipt voids the
 *     member's unused electronic credential in the same transaction; a
 *     member who already voted electronically is refused LOUDLY (with an
 *     audit entry) instead of silently "recorded"; and the online cast path
 *     refuses a member already marked as voted by paper.
 *  2. The paper route accepts only members on the PAPER path of the
 *     election's frozen eligibility_snapshot who are in good standing, and
 *     the page's paper list comes from that snapshot, not the live roster.
 *  3. Void/reissue accepts only members on the ELECTRONIC path of the
 *     frozen snapshot who are in good standing (enforced server side), and
 *     refuses members already recorded as having voted.
 *  4. Tie flagging in every threshold mode (plurality, majority, two-thirds,
 *     single and multi seat): a tie at the winning cutoff or the runoff
 *     cutoff is flagged on the results, the results page, and the records
 *     archive, and never broken silently by sort order.
 *  5. Multi-seat majority runoff: the runoff field is the top NON-WINNING
 *     candidates, up to two per unfilled seat, including ties at the cutoff;
 *     single-seat behavior (top two) is unchanged.
 *  6. Key hygiene: the private key reconstructed from the Shamir shares for
 *     the tally is zeroized as soon as decryption is done.
 */
'use strict';
const crypto = require('crypto');
process.env.DATA_DIR = require('path').join(__dirname, '..', 'data-test-regression');
process.env.PORT = '3998';
/* Supply a throwaway reissue key, as a real deployment would via the
 * environment; the test also uses it to plant "legacy" credentials. */
process.env.REISSUE_KEY = process.env.REISSUE_KEY || crypto.randomBytes(32).toString('hex');
const PLATFORM_KEY = 'platform-owner-regression-key-01';
process.env.PLATFORM_OWNER_KEY = PLATFORM_KEY;
const fs = require('fs');
fs.rmSync(process.env.DATA_DIR, { recursive: true, force: true });

/*
 * FIX 6 OBSERVER: wrap combineShares BEFORE the server (and therefore the
 * admin router) loads, so the test holds the exact key buffer the tally
 * route received and can verify it was wiped afterwards.
 */
const cryptoMod = require('../src/crypto');
const realCombineShares = cryptoMod.combineShares;
const reconstructedKeys = []; // { key, nonZeroAtCreation }
cryptoMod.combineShares = (shareTexts) => {
  const key = realCombineShares(shareTexts);
  reconstructedKeys.push({ key, nonZeroAtCreation: key.some((b) => b !== 0) });
  return key;
};

const app = require('../server');
const { db, verifyAuditChain } = require('../src/db');
const { aesEncrypt, generateCredential, hashCredential, randomHex } = require('../src/crypto');
const assert = require('assert');

const BASE = 'http://localhost:3998';

function jar() { return { cookie: '' }; }
const adminJar = jar();
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
  if (setc && session) session.cookie = setc.split(';')[0]; // anonymous voter requests (session=null) never touch a jar
  return { status: r.status, text: await r.text(), location: r.headers.get('location') };
}

/** POST as the committee, follow the redirect, and return the page text
 * (which renders and consumes the flash message). */
async function postAndFollow(path, body) {
  const post = await req('POST', path, body, adminJar);
  assert.strictEqual(post.status, 302, `POST ${path} redirects`);
  const page = await req('GET', post.location || '/admin', null, adminJar);
  return page.text;
}

/** Plant a credential for a member the way the pre-fix reissue code could
 * have (any member of the local, regardless of path). Lets the tests prove
 * the double-vote guards hold even against data predating the fixes. */
function insertLegacyCredential(electionId, memberId) {
  const credential = generateCredential();
  const salt = randomHex(16);
  const info = db.prepare('INSERT INTO credentials (election_id, code_hash, salt, member_ref) VALUES (?,?,?,?)')
    .run(electionId, hashCredential(credential, salt), salt, aesEncrypt(String(memberId), process.env.REISSUE_KEY));
  return { credential, id: info.lastInsertRowid };
}

(async () => {
  const server = app.listen(3998);
  try {
    /* ---------------- bootstrap: platform, one local, committee ---------- */
    await req('POST', '/platform/setup', { key: PLATFORM_KEY, username: 'operator', password: 'platform-pass-01', display_name: 'Operator' }, platformJar);
    await req('POST', '/platform/auth', { username: 'operator', password: 'platform-pass-01' }, platformJar);
    await req('POST', '/platform/locals', {
      name: 'Regression Fire Fighters Local 300', local_number: '300', jurisdiction: 'OH',
      admin_display_name: 'Chair', admin_username: 'chair', admin_password: 'committee-pass-1',
    }, platformJar);
    const local = db.prepare('SELECT * FROM locals ORDER BY id LIMIT 1').get();
    assert.ok(local, 'local created');
    let r = await req('POST', '/login', { username: 'chair', password: 'committee-pass-1' }, adminJar);
    assert.strictEqual(r.location, '/admin', 'committee signed in');

    /* Roster: two electronic members, five paper members. */
    await req('POST', '/admin/members/import', {
      roster: [
        'Ann Online, ann@r.test, 1',
        'Ben Online, ben@r.test, 2',
        'Cal Paperlegacy, , 3',
        'Dot Paperlegacy, , 4',
        'Eve Paperlegacy, , 5',
        'Gil Paper, , 6',
        'Hal Suspended, , 7',
      ].join('\n'),
    }, adminJar);
    const member = (name) => db.prepare('SELECT * FROM members WHERE name=?').get(name);
    const ann = member('Ann Online'); const ben = member('Ben Online');
    const cal = member('Cal Paperlegacy'); const dot = member('Dot Paperlegacy');
    const eve = member('Eve Paperlegacy'); const gil = member('Gil Paper');
    const hal = member('Hal Suspended');

    /* ================================================================
     * ELECTION 1: paper receipts, double-vote guards, reissue gates.
     * TEST election so unverified (syntax-valid) emails get credentials.
     * ================================================================ */
    r = await req('POST', '/admin/elections/new', {
      title: 'Paper and Reissue Fixture', kind: 'other', jurisdiction: 'OH', is_test: '1',
      race_title: 'Fixture Question', race_seats: '1', race_threshold: 'majority', race_candidates: 'E1 Cand X\nE1 Cand Y',
      key_shares_total: '3', key_threshold: '2', keyholders: '',
    }, adminJar);
    const e1 = db.prepare('SELECT id FROM elections ORDER BY id DESC LIMIT 1').get().id;

    r = await req('POST', `/admin/elections/${e1}/issue-credentials`, {}, adminJar);
    const e1Creds = [...r.text.matchAll(/[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}/g)].map((m) => m[0]);
    assert.strictEqual(e1Creds.length, 2, 'E1: electronic credentials for Ann and Ben only');
    const annCred = e1Creds[0]; const benCred = e1Creds[1]; // export lists members in name order
    const e1Snapshot = JSON.parse(db.prepare('SELECT eligibility_snapshot FROM elections WHERE id=?').get(e1).eligibility_snapshot);
    assert.strictEqual(e1Snapshot.filter((s) => s.method === 'electronic').length, 2, 'snapshot froze 2 electronic members');
    assert.strictEqual(e1Snapshot.filter((s) => s.method === 'paper').length, 5, 'snapshot froze 5 paper members');

    /* AFTER the freeze: suspend Hal, and add Late Larry to the live roster.
     * Neither event may widen this election's paper path. */
    await postAndFollow(`/admin/members/${hal.id}/update`, { email: '', good_standing: '0', needs_paper_ballot: '1' });
    await req('POST', '/admin/members/import', { roster: 'Late Larry, , 99' }, adminJar);
    const larry = member('Late Larry');
    assert.ok(!e1Snapshot.some((s) => s.member_id === larry.id), 'Larry is not in the frozen snapshot');

    /* Legacy credentials for three PAPER-path members, as the old reissue
     * code could have issued. */
    const calCred = insertLegacyCredential(e1, cal.id);
    const dotCred = insertLegacyCredential(e1, dot.id);
    const eveCred = insertLegacyCredential(e1, eve.id);

    await req('POST', `/admin/elections/${e1}/open`, {}, adminJar);
    const e1Race = db.prepare('SELECT * FROM races WHERE election_id=?').get(e1);
    const e1CandX = db.prepare('SELECT * FROM candidates WHERE race_id=? ORDER BY position').all(e1Race.id)[0];
    const e1Ballots = () => db.prepare('SELECT COUNT(*) n FROM ballots WHERE election_id=?').get(e1).n;
    const turnoutOf = (memberId) => db.prepare('SELECT * FROM turnout WHERE election_id=? AND member_id=?').all(e1, memberId);

    /* Ann and Cal vote electronically. Eve has a pre-fix paper turnout row
     * (recorded by the old code, which never voided her credential). */
    r = await req('POST', '/vote/cast', { credential: annCred, ['race_' + e1Race.id]: String(e1CandX.id) }, null);
    assert.ok(r.text.includes('Your ballot was cast'), 'Ann cast electronically');
    r = await req('POST', '/vote/cast', { credential: calCred.credential, ['race_' + e1Race.id]: String(e1CandX.id) }, null);
    assert.ok(r.text.includes('Your ballot was cast'), 'Cal cast electronically with the legacy credential');
    db.prepare("INSERT INTO turnout (election_id, member_id, voted_on, method) VALUES (?,?,date('now'),'paper')").run(e1, eve.id);
    assert.strictEqual(e1Ballots(), 2);

    /* ---- FIX 1: paper receipt REFUSED for a member who voted online ---- */
    let page = await postAndFollow(`/admin/elections/${e1}/paper-received`, { member_id: String(cal.id) });
    assert.ok(page.includes('do not count this paper ballot'), 'committee is told NOT to count the paper ballot');
    assert.strictEqual(turnoutOf(cal.id).length, 1, 'no second turnout row for Cal');
    assert.strictEqual(turnoutOf(cal.id)[0].method, 'electronic', 'Cal stays recorded as an electronic voter');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.paper_ballot_refused' AND detail LIKE ?")
      .get(`%member #${cal.id} refused: the member already voted electronically%`).n >= 1,
    'REGRESSION (fix 1): refusal of a paper ballot after an electronic vote is audited');

    /* ---- FIX 1: paper receipt VOIDS the unused electronic credential ---- */
    page = await postAndFollow(`/admin/elections/${e1}/paper-received`, { member_id: String(dot.id) });
    assert.ok(page.includes('Paper ballot receipt recorded.'), 'Dot\u2019s paper receipt recorded');
    assert.ok(page.includes('unused electronic credential was voided'), 'committee told the credential was voided');
    assert.strictEqual(turnoutOf(dot.id).length, 1);
    assert.strictEqual(turnoutOf(dot.id)[0].method, 'paper');
    const dotCredRow = db.prepare('SELECT * FROM credentials WHERE id=?').get(dotCred.id);
    assert.strictEqual(dotCredRow.voided, 1, 'REGRESSION (fix 1): Dot\u2019s unused electronic credential voided in the same transaction');
    assert.strictEqual(dotCredRow.redeemed, 0);
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.paper_ballot_received' AND detail LIKE '%voided in the same transaction%'").get().n >= 1,
      'credential voiding recorded in the audit log');
    /* The voided credential can no longer open or cast a ballot. */
    r = await req('POST', '/vote', { credential: dotCred.credential }, null);
    assert.strictEqual(r.status, 302, 'Dot\u2019s voided credential no longer opens a ballot');
    r = await req('POST', '/vote/cast', { credential: dotCred.credential, ['race_' + e1Race.id]: String(e1CandX.id) }, null);
    assert.strictEqual(r.status, 302, 'Dot\u2019s voided credential cannot cast');
    assert.strictEqual(e1Ballots(), 2, 'no ballot landed from the voided credential');
    assert.strictEqual(db.prepare('SELECT redeemed FROM credentials WHERE id=?').get(dotCred.id).redeemed, 0);

    /* ---- FIX 1: the cast path itself refuses a paper-voted member ----
     * Eve holds a LIVE legacy credential and a paper turnout row (the exact
     * state the old code produced). Casting must be refused with nothing
     * written: no ballot, no redemption. */
    r = await req('POST', '/vote/cast', { credential: eveCred.credential }, null);
    assert.strictEqual(r.status, 302, 'Eve\u2019s cast is refused');
    assert.strictEqual(e1Ballots(), 2, 'REGRESSION (fix 1): no electronic ballot lands for a member who voted by paper');
    assert.strictEqual(db.prepare('SELECT redeemed FROM credentials WHERE id=?').get(eveCred.id).redeemed, 0, 'Eve\u2019s credential was not redeemed');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='vote.cast_refused_already_voted'").get().n >= 1,
      'refused electronic cast is audited (member not identified)');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='vote.cast_refused_already_voted' AND (detail LIKE '%Eve%' OR detail LIKE '%member #%')").get().n === 0,
      'cast-refusal audit entry never names the member');

    /* ---- FIX 1: a second paper ballot from the same member is refused ---- */
    page = await postAndFollow(`/admin/elections/${e1}/paper-received`, { member_id: String(gil.id) });
    assert.ok(page.includes('Paper ballot receipt recorded.'), 'Gil\u2019s paper receipt recorded');
    page = await postAndFollow(`/admin/elections/${e1}/paper-received`, { member_id: String(gil.id) });
    assert.ok(page.includes('do not count a second paper ballot'), 'duplicate paper ballot refused with a clear message');
    assert.strictEqual(turnoutOf(gil.id).length, 1, 'Gil recorded exactly once');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.paper_ballot_refused' AND detail LIKE '%already recorded%'").get().n >= 1,
      'duplicate paper ballot refusal is audited');

    /* ---- FIX 2: paper route accepts only frozen-snapshot PAPER members in
     * good standing ---- */
    page = await postAndFollow(`/admin/elections/${e1}/paper-received`, { member_id: String(ben.id) });
    assert.ok(page.includes('was issued an electronic credential'), 'electronic-path member refused on the paper route');
    assert.strictEqual(turnoutOf(ben.id).length, 0, 'REGRESSION (fix 2): no turnout row for an electronic-path member via the paper route');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.paper_ballot_refused' AND detail LIKE ?")
      .get(`%member #${ben.id} refused: the member is on the electronic path%`).n >= 1, 'refusal audited');

    await postAndFollow(`/admin/elections/${e1}/paper-received`, { member_id: String(larry.id) });
    assert.strictEqual(turnoutOf(larry.id).length, 0, 'REGRESSION (fix 2): a member added after the freeze cannot be recorded');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.paper_ballot_refused' AND detail LIKE ?")
      .get(`%member #${larry.id} refused: the member is not in the frozen eligibility snapshot%`).n >= 1, 'off-snapshot refusal audited');

    await postAndFollow(`/admin/elections/${e1}/paper-received`, { member_id: String(hal.id) });
    assert.strictEqual(turnoutOf(hal.id).length, 0, 'REGRESSION (fix 2): a suspended member cannot be recorded');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.paper_ballot_refused' AND detail LIKE ?")
      .get(`%member #${hal.id} refused: the member is not in good standing%`).n >= 1, 'bad-standing refusal audited');

    /* The page's paper list comes from the frozen snapshot, filtered to good
     * standing: Gil (paper, good standing) is offered; Larry (post-freeze)
     * and Hal (suspended) are not on the page at all. */
    r = await req('GET', `/admin/elections/${e1}`, null, adminJar);
    assert.ok(r.text.includes('Gil Paper'), 'frozen-snapshot paper member listed');
    assert.ok(!r.text.includes('Late Larry'), 'REGRESSION (fix 2): post-freeze roster member not offered on the paper list');
    assert.ok(!r.text.includes('Hal Suspended'), 'REGRESSION (fix 2): suspended member not offered on the paper list');

    /* ---- FIX 3: reissue accepts only frozen-snapshot ELECTRONIC members in
     * good standing, and never a member who already voted ---- */
    const e1CredCount = () => db.prepare('SELECT COUNT(*) n FROM credentials WHERE election_id=?').get(e1).n;
    let credsBefore = e1CredCount();
    page = await postAndFollow(`/admin/elections/${e1}/reissue`, { member_id: String(gil.id) });
    assert.ok(page.includes('is on the paper-ballot path'), 'paper-path member refused a reissue');
    assert.strictEqual(e1CredCount(), credsBefore, 'REGRESSION (fix 3): no credential issued to a paper-path member');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.reissue_blocked' AND detail LIKE ?")
      .get(`%member #${gil.id} blocked: the member is on the paper-ballot path%`).n >= 1, 'paper-path reissue refusal audited');

    await postAndFollow(`/admin/elections/${e1}/reissue`, { member_id: String(larry.id) });
    assert.strictEqual(e1CredCount(), credsBefore, 'REGRESSION (fix 3): no credential issued to a post-freeze member');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.reissue_blocked' AND detail LIKE ?")
      .get(`%member #${larry.id} blocked: the member is not in the frozen eligibility snapshot%`).n >= 1, 'off-snapshot reissue refusal audited');

    await postAndFollow(`/admin/members/${ben.id}/update`, { email: 'ben@r.test', good_standing: '0', needs_paper_ballot: '0' });
    await postAndFollow(`/admin/elections/${e1}/reissue`, { member_id: String(ben.id) });
    assert.strictEqual(e1CredCount(), credsBefore, 'REGRESSION (fix 3): no credential issued to a suspended member');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.reissue_blocked' AND detail LIKE ?")
      .get(`%member #${ben.id} blocked: the member is not in good standing%`).n >= 1, 'bad-standing reissue refusal audited');
    await postAndFollow(`/admin/members/${ben.id}/update`, { email: 'ben@r.test', good_standing: '1', needs_paper_ballot: '0' });

    page = await postAndFollow(`/admin/elections/${e1}/reissue`, { member_id: String(ann.id) });
    assert.ok(page.includes('already recorded as having voted'), 'a voted member is refused a reissue');
    assert.strictEqual(e1CredCount(), credsBefore, 'no credential issued to a member who already voted');
    assert.ok(db.prepare("SELECT COUNT(*) n FROM audit_log WHERE event='election.reissue_blocked' AND detail LIKE ?")
      .get(`%member #${ann.id} blocked: the member is already recorded as having voted (electronic)%`).n >= 1, 'voted-member reissue refusal audited');

    /* A legitimate reissue (electronic path, good standing, has not voted)
     * still works end to end: old credential dies, new one casts. */
    r = await req('POST', `/admin/elections/${e1}/reissue`, { member_id: String(ben.id) }, adminJar);
    assert.strictEqual(r.status, 200, 'legitimate reissue shows the one-time replacement credential');
    const newBenCred = [...r.text.matchAll(/[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}/g)].map((m) => m[0])[0];
    assert.ok(newBenCred, 'replacement credential displayed');
    assert.strictEqual(e1CredCount(), credsBefore + 1, 'one replacement credential added');
    r = await req('POST', '/vote', { credential: benCred }, null);
    assert.strictEqual(r.status, 302, 'Ben\u2019s original credential is dead after the reissue');
    r = await req('POST', '/vote/cast', { credential: newBenCred, ['race_' + e1Race.id]: String(e1CandX.id) }, null);
    assert.ok(r.text.includes('Your ballot was cast'), 'Ben casts with the replacement credential');
    assert.strictEqual(e1Ballots(), 3);
    assert.strictEqual(turnoutOf(ben.id)[0].method, 'electronic');

    /* ================================================================
     * ELECTION 2: tie flags (fix 4), multi-seat runoff field (fix 5),
     * key hygiene (fix 6). Six voters, eight races covering every
     * threshold mode with ties at the winning and runoff cutoffs.
     * ================================================================ */
    await req('POST', '/admin/members/import', {
      roster: ['Voter 1, v1@r.test, 11', 'Voter 2, v2@r.test, 12', 'Voter 3, v3@r.test, 13',
        'Voter 4, v4@r.test, 14', 'Voter 5, v5@r.test, 15', 'Voter 6, v6@r.test, 16'].join('\n'),
    }, adminJar);

    const raceDefs = [
      { title: 'Trustees', seats: 2, threshold: 'plurality', cands: ['R1 Alpha', 'R1 Bravo', 'R1 Charlie', 'R1 Delta'] },
      { title: 'President', seats: 1, threshold: 'majority', cands: ['R2 Xray', 'R2 Yankee', 'R2 Zulu'] },
      { title: 'Vice President', seats: 1, threshold: 'majority', cands: ['R3 Xray', 'R3 Yankee', 'R3 Zulu'] },
      { title: 'Executive Board', seats: 3, threshold: 'majority', cands: ['R4 Adams', 'R4 Baker', 'R4 Clark', 'R4 Davis', 'R4 Evans', 'R4 Ford'] },
      { title: 'Delegates', seats: 3, threshold: 'majority', cands: ['R5 Adams', 'R5 Baker', 'R5 Clark', 'R5 Davis', 'R5 Evans', 'R5 Ford'] },
      { title: 'Grievance Committee', seats: 2, threshold: 'majority', cands: ['R6 Papa', 'R6 Quebec', 'R6 Romeo'] },
      { title: 'Bylaw Motions', seats: 2, threshold: 'two_thirds', cands: ['R7 Motion M', 'R7 Motion N'] },
      { title: 'Auditor', seats: 1, threshold: 'plurality', cands: ['R8 Golf', 'R8 Hotel'] },
    ];
    r = await req('POST', '/admin/elections/new', {
      title: 'Tie and Runoff Matrix', kind: 'other', jurisdiction: 'OH', is_test: '1',
      race_title: raceDefs.map((d) => d.title),
      race_seats: raceDefs.map((d) => String(d.seats)),
      race_threshold: raceDefs.map((d) => d.threshold),
      race_candidates: raceDefs.map((d) => d.cands.join('\n')),
      key_shares_total: '3', key_threshold: '2', keyholders: '',
    }, adminJar);
    const e2Shares = [...r.text.matchAll(/SHARE-\d+-[0-9a-f]+/g)].map((m) => m[0]);
    assert.strictEqual(e2Shares.length, 3, 'E2 key shares displayed');
    const e2 = db.prepare('SELECT id FROM elections ORDER BY id DESC LIMIT 1').get().id;

    const e2RaceRows = db.prepare('SELECT * FROM races WHERE election_id=? ORDER BY position').all(e2);
    const raceOf = {};
    for (const rc of e2RaceRows) {
      raceOf[rc.title] = { race: rc, cands: db.prepare('SELECT * FROM candidates WHERE race_id=? ORDER BY position').all(rc.id) };
    }

    r = await req('POST', `/admin/elections/${e2}/issue-credentials`, {}, adminJar);
    const e2Creds = [...r.text.matchAll(/[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}/g)].map((m) => m[0]);
    assert.strictEqual(e2Creds.length, 8, 'E2: Ann, Ben and the six voters got credentials');
    const voterCreds = e2Creds.slice(2); // name order: Ann Online, Ben Online, Voter 1..6
    await req('POST', `/admin/elections/${e2}/open`, {}, adminJar);

    /* Per-voter picks, by candidate index within each race (a race missing
     * from a plan is left blank on that ballot; undervoting is allowed).
     * Totals engineered per race:
     *   Trustees (plurality, 2 seats): Alpha 3, Bravo 2, Charlie 2, Delta 1
     *     -> seat 2 TIED between Bravo and Charlie.
     *   President (majority, 1 seat): Xray 2, Yankee 1, Zulu 1 of 4
     *     -> runoff, with Yankee and Zulu TIED at the runoff cutoff.
     *   Vice President (majority, 1 seat): Xray 2, Yankee 2, Zulu 0 of 4
     *     -> clean runoff between the top two, unchanged.
     *   Executive Board (majority, 3 seats): Adams 6 wins; 2 seats unfilled
     *     -> runoff field is the top FOUR non-winners (2 per unfilled seat).
     *   Delegates (majority, 3 seats): same, but Evans and Ford TIED at the
     *     runoff cutoff -> all five non-winners in the runoff plus a flag.
     *   Grievance Committee (majority, 2 seats): Papa 4, Quebec 3, Romeo 3,
     *     ALL above the multi-seat majority (10 votes / 4 = 2.5)
     *     -> Papa elected, seat 2 TIED between Quebec and Romeo, NO runoff.
     *   Bylaw Motions (two_thirds): Motion M 4, Motion N 4 of 4 ballots,
     *     both at or above two-thirds -> TIED at the adoption threshold.
     *   Auditor (plurality, 1 seat): Golf 2, Hotel 2 -> seat 1 TIED. */
    const plans = [
      { Trustees: [0, 1], President: [0], 'Vice President': [0], 'Executive Board': [0, 1, 2], Delegates: [0, 1, 2], 'Grievance Committee': [0, 1], 'Bylaw Motions': [0, 1], Auditor: [0] },
      { Trustees: [0, 2], President: [0], 'Vice President': [0], 'Executive Board': [0, 1, 2], Delegates: [0, 1, 2], 'Grievance Committee': [0, 1], 'Bylaw Motions': [0, 1], Auditor: [0] },
      { Trustees: [0, 3], President: [1], 'Vice President': [1], 'Executive Board': [0, 3, 4], Delegates: [0, 3, 4], 'Grievance Committee': [0, 2], 'Bylaw Motions': [0, 1], Auditor: [1] },
      { Trustees: [1, 2], President: [2], 'Vice President': [1], 'Executive Board': [0, 3], Delegates: [0, 3, 5], 'Grievance Committee': [0, 2], 'Bylaw Motions': [0, 1], Auditor: [1] },
      { 'Executive Board': [0], Delegates: [0], 'Grievance Committee': [1, 2] },
      { 'Executive Board': [0], Delegates: [0] },
    ];
    for (let i = 0; i < plans.length; i++) {
      const body = { credential: voterCreds[i] };
      for (const [title, picks] of Object.entries(plans[i])) {
        const rc = raceOf[title];
        body['race_' + rc.race.id] = picks.map((p) => String(rc.cands[p].id));
      }
      const rr = await req('POST', '/vote/cast', body, null);
      assert.ok(rr.text.includes('Your ballot was cast'), `E2 ballot ${i + 1} cast`);
    }

    await req('POST', `/admin/elections/${e2}/close`, {}, adminJar);
    r = await req('POST', `/admin/elections/${e2}/tally`, { share: [e2Shares[0], e2Shares[2]] }, adminJar);

    const results = JSON.parse(db.prepare('SELECT results_json FROM elections WHERE id=?').get(e2).results_json);
    assert.strictEqual(results.ballots_cast, 6);
    assert.ok(results.integrity_ok, 'E2 integrity check passes');
    const byTitle = {};
    results.races.forEach((rc) => { byTitle[rc.title] = rc; });

    /* ---- FIX 4: plurality multi-seat tie at the last seat ---- */
    const r1 = byTitle['Trustees'];
    assert.deepStrictEqual(r1.winners, ['R1 Alpha'], 'plurality: only the clear leader is declared');
    assert.deepStrictEqual(r1.tie_flags, ['Tie for seat 2 between R1 Bravo and R1 Charlie, resolve per your bylaws.'],
      'REGRESSION (fix 4): plurality tie at the last seat is flagged, never broken by list order');
    assert.strictEqual(r1.runoff_required, false);

    /* ---- FIX 4 + 5: single-seat runoff, tie at the runoff cutoff ---- */
    const r2 = byTitle['President'];
    assert.deepStrictEqual(r2.winners, []);
    assert.strictEqual(r2.runoff_required, true);
    assert.strictEqual(r2.runoff_seats, 1);
    assert.deepStrictEqual(r2.runoff_between, ['R2 Xray', 'R2 Yankee', 'R2 Zulu'],
      'REGRESSION (fix 4): candidates tied at the runoff cutoff are all included, not cut by sort order');
    assert.deepStrictEqual(r2.tie_flags, ['Tie at the runoff cutoff between R2 Yankee and R2 Zulu; all tied candidates are included in the runoff, resolve per your bylaws.']);

    /* ---- FIX 5: single-seat clean runoff stays top two ---- */
    const r3 = byTitle['Vice President'];
    assert.deepStrictEqual(r3.winners, []);
    assert.deepStrictEqual(r3.runoff_between, ['R3 Xray', 'R3 Yankee'], 'single-seat runoff behavior (top two) unchanged');
    assert.deepStrictEqual(r3.tie_flags, []);
    assert.strictEqual(r3.runoff_seats, 1);

    /* ---- FIX 5: multi-seat runoff field = top non-winners, two per
     * unfilled seat ---- */
    const r4 = byTitle['Executive Board'];
    assert.deepStrictEqual(r4.winners, ['R4 Adams']);
    assert.strictEqual(r4.runoff_required, true);
    assert.strictEqual(r4.runoff_seats, 2, 'two seats unfilled');
    assert.deepStrictEqual(r4.runoff_between, ['R4 Baker', 'R4 Clark', 'R4 Davis', 'R4 Evans'],
      'REGRESSION (fix 5): runoff names the top FOUR non-winning candidates (2 x 2 unfilled seats), not just the top two');
    assert.ok(!r4.runoff_between.includes('R4 Adams'), 'an elected candidate is never in the runoff field');
    assert.deepStrictEqual(r4.tie_flags, []);

    /* ---- FIX 5: multi-seat runoff cutoff tie includes all tied ---- */
    const r5 = byTitle['Delegates'];
    assert.deepStrictEqual(r5.winners, ['R5 Adams']);
    assert.strictEqual(r5.runoff_seats, 2);
    assert.deepStrictEqual(r5.runoff_between, ['R5 Baker', 'R5 Clark', 'R5 Davis', 'R5 Evans', 'R5 Ford'],
      'REGRESSION (fix 5): ties at the runoff cutoff are included');
    assert.deepStrictEqual(r5.tie_flags, ['Tie at the runoff cutoff between R5 Evans and R5 Ford; all tied candidates are included in the runoff, resolve per your bylaws.']);

    /* ---- FIX 4: multi-seat majority tie at the last seat, no runoff ---- */
    const r6 = byTitle['Grievance Committee'];
    assert.deepStrictEqual(r6.winners, ['R6 Papa'], 'only the clear majority leader is declared');
    assert.deepStrictEqual(r6.tie_flags, ['Tie for seat 2 between R6 Quebec and R6 Romeo, resolve per your bylaws.'],
      'REGRESSION (fix 4): majority-mode tie at the last seat is flagged');
    assert.strictEqual(r6.runoff_required, false, 'a seat tied between majority holders is a bylaws matter, not a runoff');

    /* ---- FIX 4: two-thirds tie at the adoption threshold ---- */
    const r7 = byTitle['Bylaw Motions'];
    assert.deepStrictEqual(r7.winners, [], 'no option silently adopted by list order');
    assert.deepStrictEqual(r7.tie_flags, ['Tie at the two-thirds threshold between R7 Motion M and R7 Motion N, resolve per your bylaws.'],
      'REGRESSION (fix 4): two-thirds tie is flagged');

    /* ---- FIX 4: plurality single-seat dead heat ---- */
    const r8 = byTitle['Auditor'];
    assert.deepStrictEqual(r8.winners, [], 'no winner declared in a dead heat');
    assert.deepStrictEqual(r8.tie_flags, ['Tie for seat 1 between R8 Golf and R8 Hotel, resolve per your bylaws.'],
      'REGRESSION (fix 4): single-seat plurality tie is flagged');

    /* ---- FIX 4: flags render on the results page and land in the records
     * archive ---- */
    r = await req('GET', `/admin/elections/${e2}`, null, adminJar);
    assert.ok(r.text.includes('Tie for seat 2 between R1 Bravo and R1 Charlie, resolve per your bylaws.'), 'tie flag shown on the results page');
    assert.ok(r.text.includes('No majority for 2 seats, runoff required'), 'multi-seat runoff notice shown');
    assert.ok(r.text.includes('No majority for 1 seat, runoff required'), 'single-seat runoff notice shown');
    assert.ok(r.text.includes('among R4 Baker, R4 Clark, R4 Davis, R4 Evans'), 'runoff field listed on the page');

    const arch = await req('GET', `/admin/elections/${e2}/archive`, null, adminJar);
    const archive = JSON.parse(arch.text);
    const archTrustees = archive.results.races.find((rc) => rc.title === 'Trustees');
    assert.deepStrictEqual(archTrustees.tie_flags, ['Tie for seat 2 between R1 Bravo and R1 Charlie, resolve per your bylaws.'],
      'REGRESSION (fix 4): tie flag preserved in the records archive results');
    const archDelegates = archive.results.races.find((rc) => rc.title === 'Delegates');
    assert.deepStrictEqual(archDelegates.runoff_between, ['R5 Baker', 'R5 Clark', 'R5 Davis', 'R5 Evans', 'R5 Ford'],
      'runoff field preserved in the records archive results');

    /* ---- FIX 6: the reconstructed private key is wiped after the tally ---- */
    assert.strictEqual(reconstructedKeys.length, 1, 'the tally reconstructed the private key exactly once');
    assert.ok(reconstructedKeys[0].nonZeroAtCreation, 'sanity: the reconstructed key held real key material');
    assert.ok(reconstructedKeys[0].key.every((b) => b === 0),
      'REGRESSION (fix 6): the reconstructed private key buffer is zeroized once the tally is done');

    /* Audit chains still verify after every refusal and receipt. */
    assert.ok(verifyAuditChain(local.id).ok, 'local audit chain verifies');
    assert.ok(verifyAuditChain(null).ok, 'platform audit chain verifies');

    console.log('\nALL REGRESSION TESTS PASSED \u2714');
    console.log('  Fix 1: paper receipt voids the unused electronic credential in the same transaction;');
    console.log('         a member who voted online is refused loudly (audited); the cast path refuses');
    console.log('         a member already marked as voted by paper (nothing written, nothing redeemed).');
    console.log('  Fix 2: paper route and paper list honor the frozen eligibility snapshot (paper path,');
    console.log('         good standing); post-freeze and suspended members are rejected server side.');
    console.log('  Fix 3: reissue honors the frozen snapshot (electronic path, good standing) server side');
    console.log('         and refuses members already recorded as having voted.');
    console.log('  Fix 4: ties at the winning cutoff and the runoff cutoff are flagged in every threshold');
    console.log('         mode (plurality/majority/two-thirds, single and multi seat), on the results,');
    console.log('         the results page, and the records archive; no winner is picked by sort order.');
    console.log('  Fix 5: multi-seat majority runoffs name the top non-winning candidates, two per');
    console.log('         unfilled seat, ties included; single-seat runoffs stay top two.');
    console.log('  Fix 6: the tally zeroizes the reconstructed election private key after decryption.');
  } finally {
    server.close();
    fs.rmSync(process.env.DATA_DIR, { recursive: true, force: true });
  }
})().catch((e) => { console.error('REGRESSION TEST FAILED:', e); process.exit(1); });
