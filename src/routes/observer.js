/**
 * routes/observer.js — Candidate observers (29 U.S.C. 481(c)).
 *
 * Observers get read-only visibility into every observable part of the
 * process: election configuration, keyholder list, credential issuance
 * counts (never the credentials themselves), the who-has-voted turnout list
 * they are traditionally entitled to compile, results, and the full
 * tamper-evident audit log with live chain verification.
 */
'use strict';

const express = require('express');
const { db, verifyAuditChain } = require('../db');

module.exports = function observerRoutes() {
  const router = express.Router();

  router.get('/', (req, res) => {
    const elections = db.prepare('SELECT * FROM elections ORDER BY id DESC').all();
    for (const e of elections) {
      e.turnout = db.prepare('SELECT COUNT(*) AS n FROM turnout WHERE election_id=?').get(e.id).n;
      e.eligible = JSON.parse(e.eligibility_snapshot || '[]').length;
      e.ballots = db.prepare('SELECT COUNT(*) AS n FROM ballots WHERE election_id=?').get(e.id).n;
      e.redeemed = db.prepare('SELECT COUNT(*) AS n FROM credentials WHERE election_id=? AND redeemed=1').get(e.id).n;
    }
    res.render('observer/dashboard', { title: 'Observer station', elections, chain: verifyAuditChain() });
  });

  router.get('/elections/:id', (req, res) => {
    const e = db.prepare('SELECT * FROM elections WHERE id=?').get(req.params.id);
    if (!e) return res.redirect('/observe');
    e.races = db.prepare('SELECT * FROM races WHERE election_id=? ORDER BY position, id').all(e.id);
    for (const r of e.races) r.candidates = db.prepare('SELECT * FROM candidates WHERE race_id=? ORDER BY position, id').all(r.id);
    const turnout = db.prepare('SELECT m.name, t.voted_on, t.method FROM turnout t JOIN members m ON m.id=t.member_id WHERE t.election_id=? ORDER BY m.name').all(e.id);
    const credStats = db.prepare('SELECT COUNT(*) AS total, COALESCE(SUM(redeemed),0) AS used, COALESCE(SUM(voided),0) AS voided FROM credentials WHERE election_id=?').get(e.id);
    const ballots = db.prepare('SELECT COUNT(*) AS n FROM ballots WHERE election_id=?').get(e.id).n;
    res.render('observer/election', {
      title: `Observing: ${e.title}`, e, turnout, credStats, ballots,
      eligible: JSON.parse(e.eligibility_snapshot || '[]').length,
      results: e.results_json ? JSON.parse(e.results_json) : null,
    });
  });

  router.get('/audit', (req, res) => {
    const rows = db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 1000').all();
    res.render('observer/audit', { title: 'Audit log', rows, chain: verifyAuditChain() });
  });

  return router;
};
