/**
 * tenant.js — THE multi-local scoping layer. Every committee/observer route
 * resolves "the current local" through here, and every fetch of a member,
 * election, or account goes through a helper that carries the local_id check
 * in the SQL itself.
 *
 * THE RULE THIS FILE ENFORCES: a committee or observer account authenticated
 * for Local A must be STRUCTURALLY incapable of reading or writing Local B's
 * roster, elections, accounts, credentials, or archives — no matter what id
 * it guesses or URL it types. Rows that hang off an election (races,
 * candidates, credentials, ballots, turnout) are reachable in application
 * code only through an election row returned by getElection(localId, id),
 * so the election check scopes them transitively.
 *
 * WHAT THIS FILE MUST NEVER DO: create any new path between a voter and a
 * ballot. Nothing here touches the ballots table, and the local id is an
 * organizational fact (which union a roster belongs to), never a per-voter
 * fact. Ballot rows deliberately carry no local_id.
 */
'use strict';

const { db } = require('./db');

/** Error that renders as a 404 — the resource does not exist AS FAR AS THIS
 * LOCAL IS CONCERNED. Deliberately indistinguishable from a genuinely absent
 * id, so probing URLs cannot confirm that another local's row exists. */
function notFound(publicMessage) {
  return Object.assign(new Error(publicMessage), { status: 404, publicMessage });
}

/* ---------------- locals ---------------- */

function getLocal(id) {
  return db.prepare('SELECT * FROM locals WHERE id=?').get(id) || null;
}

function listLocals() {
  return db.prepare('SELECT * FROM locals ORDER BY id').all();
}

function createLocal({ name, localNumber, jurisdiction }) {
  const info = db.prepare('INSERT INTO locals (name, local_number, jurisdiction) VALUES (?,?,?)')
    .run(String(name).trim(), localNumber ? String(localNumber).trim() : null, jurisdiction || null);
  return getLocal(info.lastInsertRowid);
}

/* ---------------- platform administrators ---------------- */

function platformAdminExists() {
  return !!db.prepare('SELECT id FROM platform_users LIMIT 1').get();
}

/** True when the database holds no tenant data at all — the only state in
 * which an unauthenticated first-run platform bootstrap is acceptable. */
function instanceIsEmpty() {
  return !platformAdminExists()
    && !db.prepare('SELECT id FROM locals LIMIT 1').get()
    && !db.prepare('SELECT id FROM users LIMIT 1').get()
    && !db.prepare('SELECT id FROM members LIMIT 1').get()
    && !db.prepare('SELECT id FROM elections LIMIT 1').get();
}

/* ---------------- the current-local middleware ---------------- */

/**
 * Express middleware for every committee/observer route (mounted after the
 * role check). Re-reads the account row on each request — so a deleted
 * account or local takes effect immediately, and a stale session can never
 * carry a local_id the database no longer agrees with — then exposes:
 *
 *   req.localId            the ONLY local this request may touch
 *   req.local              its row (name shown in the header of every page)
 *   res.locals.currentLocal  for the views
 */
function resolveLocal(req, res, next) {
  const sess = req.session && req.session.user;
  if (!sess) return res.redirect('/login');
  const account = db.prepare('SELECT * FROM users WHERE id=?').get(sess.id);
  const local = account ? getLocal(account.local_id) : null;
  if (!account || !local) {
    req.session.destroy(() => res.redirect('/login'));
    return;
  }
  req.localId = local.id;
  req.local = local;
  res.locals.currentLocal = local;
  next();
}

/* ---------------- scoped fetch helpers ----------------
 * localId first, always: the scope is not an afterthought. Each returns the
 * row only when it belongs to the given local. */

/** Election row, or throws a 404 that never confirms the id exists elsewhere. */
function getElection(localId, electionId) {
  const e = db.prepare('SELECT * FROM elections WHERE id=? AND local_id=?').get(electionId, localId);
  if (!e) throw notFound('Election not found.');
  return e;
}

/** Election row or null (for routes that redirect instead of erroring). */
function findElection(localId, electionId) {
  return db.prepare('SELECT * FROM elections WHERE id=? AND local_id=?').get(electionId, localId) || null;
}

/** Member row or null. */
function getMember(localId, memberId) {
  return db.prepare('SELECT * FROM members WHERE id=? AND local_id=?').get(memberId, localId) || null;
}

/** Committee/observer account row or null. */
function getUser(localId, userId) {
  return db.prepare('SELECT * FROM users WHERE id=? AND local_id=?').get(userId, localId) || null;
}

module.exports = {
  notFound,
  getLocal,
  listLocals,
  createLocal,
  platformAdminExists,
  instanceIsEmpty,
  resolveLocal,
  getElection,
  findElection,
  getMember,
  getUser,
};
