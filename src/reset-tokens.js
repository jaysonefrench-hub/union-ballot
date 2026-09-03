/**
 * reset-tokens.js — Single-use committee password-reset tokens.
 *
 * Same discipline as the member email-verification tokens: 128 bits from the
 * CSPRNG, stored ONLY as an unsalted SHA-256 hash (direct lookup; the input
 * space cannot be brute forced), single use, and expiring. The plaintext
 * token exists only inside the reset link — in the email, or on the platform
 * administrator's one-time display — and is never written to the database,
 * the audit log, or the console.
 *
 * The system never emails, displays, or stores a recoverable password:
 * a reset link only lets its holder CHOOSE a new password on the token page.
 */
'use strict';

const { db } = require('./db');
const { generateVerifyToken, hashVerifyToken } = require('./crypto');

const BASE_URL = () => process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;

/* Short-lived by design: unlike roster email verification (days), a password
 * reset is requested and completed in one sitting. */
const RESET_TOKEN_TTL_MINUTES = Math.max(5, Number(process.env.RESET_TOKEN_TTL_MINUTES || 60));

/**
 * Start (or restart) a password reset for one account: a fresh token
 * invalidates any previous one. Returns the reset URL for delivery; the
 * caller decides how (email, or the platform admin's one-time display) and
 * writes the audit entry — never including the token itself.
 */
function beginPasswordReset(userId) {
  const token = generateVerifyToken();
  db.prepare("UPDATE users SET reset_token_hash=?, reset_token_sent_at=datetime('now') WHERE id=?")
    .run(hashVerifyToken(token), userId);
  return `${BASE_URL()}/reset-password?token=${token}`;
}

/**
 * Validate a presented token. Returns { ok: true, user } or
 * { ok: false, reason: 'format' | 'unknown' | 'expired' }.
 * Does NOT consume the token — that happens only when a new password is set.
 */
function findUserByValidResetToken(token) {
  const t = String(token || '').trim();
  if (!/^[0-9a-f]{32}$/i.test(t)) return { ok: false, reason: 'format' };
  const u = db.prepare('SELECT * FROM users WHERE reset_token_hash=?').get(hashVerifyToken(t));
  if (!u) return { ok: false, reason: 'unknown' };
  const sentAt = u.reset_token_sent_at ? new Date(u.reset_token_sent_at.replace(' ', 'T') + 'Z') : null;
  if (!sentAt || (Date.now() - sentAt.getTime()) > RESET_TOKEN_TTL_MINUTES * 60 * 1000) {
    /* user is included so the caller can attribute the audit entry to the
     * account's local; it is never rendered for an invalid token. */
    return { ok: false, reason: 'expired', user: u };
  }
  return { ok: true, user: u };
}

function clearResetToken(userId) {
  db.prepare('UPDATE users SET reset_token_hash=NULL, reset_token_sent_at=NULL WHERE id=?').run(userId);
}

module.exports = { beginPasswordReset, findUserByValidResetToken, clearResetToken, RESET_TOKEN_TTL_MINUTES };
