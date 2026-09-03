/**
 * routes/observer.js — Candidate observers (29 U.S.C. 481(c)), for ONE local.
 *
 * Observers get read-only visibility into every observable part of THEIR
 * local's process: election configuration, keyholder list, credential
 * issuance counts (never the credentials themselves), the who-has-voted
 * turnout list they are traditionally entitled to compile, results, and
 * their local's full tamper-evident audit chain with live verification.
 *
 * TENANCY: mounted behind resolveLocal, so req.localId is the signed-in
 * account's local and every query below carries it. An observer for Local A
 * can never list, open, or verify anything belonging to Local B — another
 * local's election id renders exactly like an id that never existed. The
 * audit log is hash-chained per local, so this local's observers verify
 * their complete chain without seeing any other local's entries.
 */
'use strict';

const express = require('express');
const { db, verifyAuditChain } = require('../db');
const { markTestElectionBanner } = require('../election-demo');
const tenant = require('../tenant');

/* Voter-portal security events live on the platform chain because a rejected
 * credential or a throttled address matches NO election (and therefore no
 * local). They are anonymous by design — no name, address, or credential is
 * ever recorded — so showing them to every local's observers leaks nothing
 * and preserves the observers' tamper-alert visibility. */
const INSTANCE_SECURITY_EVENTS = ['vote.credential_rejected', 'vote.rate_limited'];

module.exports = function observerRoutes() {
  const router = express.Router();

  router.get('/', (req, res) => {
    const elections = db.prepare('SELECT * FROM elections WHERE local_id=? ORDER BY id DESC').all(req.localId);
    for (const e of elections) {
      e.turnout = db.prepare('SELECT COUNT(*) AS n FROM turnout WHERE election_id=?').get(e.id).n;
      e.eligible = JSON.parse(e.eligibility_snapshot || '[]').length;
      e.ballots = db.prepare('SELECT COUNT(*) AS n FROM ballots WHERE election_id=?').get(e.id).n;
      e.redeemed = db.prepare('SELECT COUNT(*) AS n FROM credentials WHERE election_id=? AND redeemed=1').get(e.id).n;
    }
    res.render('observer/dashboard', { title: 'Observer station', elections, chain: verifyAuditChain(req.localId) });
  });

  router.get('/elections/:id', (req, res) => {
    const e = tenant.findElection(req.localId, req.params.id);
    if (!e) return res.redirect('/observe');
    e.races = db.prepare('SELECT * FROM races WHERE election_id=? ORDER BY position, id').all(e.id);
    for (const r of e.races) r.candidates = db.prepare('SELECT * FROM candidates WHERE race_id=? ORDER BY position, id').all(r.id);
    const turnout = db.prepare('SELECT m.name, t.voted_on, t.method FROM turnout t JOIN members m ON m.id=t.member_id WHERE t.election_id=? ORDER BY m.name').all(e.id);
    const credStats = db.prepare('SELECT COUNT(*) AS total, COALESCE(SUM(redeemed),0) AS used, COALESCE(SUM(voided),0) AS voided FROM credentials WHERE election_id=?').get(e.id);
    const ballots = db.prepare('SELECT COUNT(*) AS n FROM ballots WHERE election_id=?').get(e.id).n;
    markTestElectionBanner(res, e);
    res.render('observer/election', {
      title: `Observing: ${e.title}`, e, turnout, credStats, ballots,
      eligible: JSON.parse(e.eligibility_snapshot || '[]').length,
      results: e.results_json ? JSON.parse(e.results_json) : null,
    });
  });

  router.get('/audit', (req, res) => {
    const rows = db.prepare('SELECT * FROM audit_log WHERE local_id=? ORDER BY id DESC LIMIT 1000').all(req.localId);
    const securityEvents = db.prepare(
      `SELECT id, at, actor, event, detail FROM audit_log
       WHERE local_id IS NULL AND event IN (${INSTANCE_SECURITY_EVENTS.map(() => '?').join(',')})
       ORDER BY id DESC LIMIT 200`
    ).all(...INSTANCE_SECURITY_EVENTS);
    res.render('observer/audit', {
      title: 'Audit log',
      rows,
      chain: verifyAuditChain(req.localId),
      securityEvents,
    });
  });

  return router;
};
