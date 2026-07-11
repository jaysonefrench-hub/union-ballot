/**
 * routes/voter.js — The voting experience. No account, no name, no login:
 * a voter presents only their anonymous one-time credential.
 */
'use strict';

const express = require('express');
const { db, audit } = require('../db');
const {
  normalizeCredential, hashCredential, encryptBallot, aesDecrypt, randomId,
} = require('../crypto');

module.exports = function voterRoutes({ flash }) {
  const router = express.Router();

  function findLiveCredential(rawCode) {
    const norm = normalizeCredential(rawCode);
    if (norm.length !== 16) return null;
    const rows = db.prepare(`
      SELECT c.*, e.status AS election_status FROM credentials c
      JOIN elections e ON e.id = c.election_id
      WHERE e.status = 'open' AND c.voided = 0
    `).all();
    for (const c of rows) {
      if (hashCredential(norm, c.salt) === c.code_hash) return c;
    }
    return null;
  }

  function loadBallotDef(electionId) {
    const election = db.prepare('SELECT * FROM elections WHERE id=?').get(electionId);
    const races = db.prepare('SELECT * FROM races WHERE election_id=? ORDER BY position, id').all(electionId);
    for (const r of races) {
      r.candidates = db.prepare('SELECT * FROM candidates WHERE race_id=? ORDER BY position, id').all(r.id);
    }
    return { election, races };
  }

  router.get('/', (req, res) => {
    const openCount = db.prepare("SELECT COUNT(*) AS n FROM elections WHERE status='open'").get().n;
    res.render('home', { title: 'Cast your ballot', openCount });
  });

  /* Step 1: credential check → show the ballot (nothing is recorded yet). */
  router.post('/vote', (req, res) => {
    const cred = findLiveCredential(req.body.credential);
    if (!cred) {
      audit('voter-portal', 'vote.credential_rejected', 'A credential was entered that did not match any live credential for an open vote');
      flash(req, 'error', 'That credential was not recognized for any open vote. Check for typos, or contact the election committee if you believe it should work.');
      return res.redirect('/');
    }
    if (cred.redeemed) {
      flash(req, 'error', 'That credential has already been used to cast a ballot. Each credential works exactly once. If you did not vote, contact the election committee immediately.');
      return res.redirect('/');
    }
    const { election, races } = loadBallotDef(cred.election_id);
    res.render('ballot', {
      title: election.title,
      election, races,
      credential: normalizeCredential(req.body.credential),
    });
  });

  /* Step 2: cast. One transaction: redeem credential, record turnout,
   * store the encrypted, unlinkable ballot. */
  router.post('/vote/cast', (req, res, next) => {
    try {
      const cred = findLiveCredential(req.body.credential);
      if (!cred || cred.redeemed) {
        flash(req, 'error', 'This credential is no longer valid (it may have just been used). No ballot was recorded from this submission.');
        return res.redirect('/');
      }
      const { election, races } = loadBallotDef(cred.election_id);

      /* Build & validate selections */
      const choices = {};
      for (const race of races) {
        let picked = req.body['race_' + race.id];
        if (picked === undefined) picked = [];
        if (!Array.isArray(picked)) picked = [picked];
        picked = picked.map(Number).filter((id) => race.candidates.some((c) => c.id === id));
        if (picked.length > race.seats) {
          flash(req, 'error', `Too many selections for "${race.title}" — choose up to ${race.seats}. Your ballot was NOT cast; please try again.`);
          return res.redirect('/');
        }
        choices[race.id] = picked; // undervoting (including blank) is allowed
      }

      const reissueKey = process.env.REISSUE_KEY || db.prepare("SELECT value FROM settings WHERE key='reissue_key'").get().value;
      const memberId = Number(aesDecrypt(cred.member_ref, reissueKey));

      const cast = db.transaction(() => {
        const upd = db.prepare('UPDATE credentials SET redeemed=1, redeemed_on=date(\'now\') WHERE id=? AND redeemed=0').run(cred.id);
        if (upd.changes !== 1) throw Object.assign(new Error('double-spend race'), { publicMessage: 'This credential was just used. No second ballot was recorded.' });
        db.prepare('INSERT OR IGNORE INTO turnout (election_id, member_id, voted_on, method) VALUES (?,?,date(\'now\'),\'electronic\')')
          .run(election.id, memberId);
        /*
         * The ballot: encrypted to the election public key, stored under a
         * random UUID with no timestamp and no reference to the credential
         * or member. This is the moment the vote becomes unlinkable.
         */
        const payload = encryptBallot({ v: 1, election_id: election.id, choices }, election.public_key);
        db.prepare('INSERT INTO ballots (id, election_id, payload) VALUES (?,?,?)').run(randomId(), election.id, payload);
      });
      cast();

      /* Log an anonymous counter event only — never who, never what. */
      audit('voter-portal', 'vote.ballot_cast', `A ballot was cast in election #${election.id} ("${election.title}")`);

      const turnout = db.prepare('SELECT COUNT(*) AS n FROM turnout WHERE election_id=?').get(election.id).n;
      const eligible = JSON.parse(election.eligibility_snapshot || '[]').length;
      res.render('cast-confirm', { title: 'Ballot cast', election, turnout, eligible });
    } catch (err) {
      next(err);
    }
  });

  return router;
};
