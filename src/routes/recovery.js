/**
 * routes/recovery.js — Committee/observer account password recovery.
 *
 * THE RULE: no plaintext password is ever emailed, displayed, stored, or
 * logged — not the old one (the system only ever held a bcrypt hash) and not
 * the new one. Recovery works exclusively through a single-use, expiring
 * reset link whose token is stored hash-only (src/reset-tokens.js), exactly
 * like the member email-verification links. The link holder chooses a new
 * password on the token page.
 *
 * Two ways a reset link comes into existence:
 *   1. Self-service (/forgot-password): if SMTP is configured AND the
 *      account has a recovery email on file, the link is emailed. The
 *      response is deliberately identical whether or not the account exists,
 *      so the public form cannot be used to enumerate usernames.
 *   2. Platform owner: with PLATFORM_OWNER_KEY, a one-time link can be
 *      generated on the /platform page and delivered out-of-band — the
 *      backstop for a local that lost its login on an instance without SMTP.
 *
 * Every request and completion is audit-logged; the token never is.
 */
'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const { db, audit } = require('../db');
const { smtpConfigured, sendPasswordResetEmail } = require('../mailer');
const { beginPasswordReset, findUserByValidResetToken, clearResetToken, RESET_TOKEN_TTL_MINUTES } = require('../reset-tokens');
const { makeRateLimiter } = require('../simple-rate-limit');

module.exports = function recoveryRoutes({ flash }) {
  const router = express.Router();

  /* Public, unauthenticated endpoints that trigger email and audit entries —
   * throttle them so one source cannot bombard an admin's inbox or spam the
   * permanent audit log. */
  const limiter = makeRateLimiter({ windowMs: 15 * 60 * 1000, max: 10 });

  /* ---------------- forgot password (request a reset link) ------------- */
  router.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { title: 'Forgot password', smtp: smtpConfigured() });
  });

  router.post('/forgot-password', async (req, res, next) => {
    try {
      if (limiter.blocked(req)) {
        flash(req, 'error', 'Too many reset requests from your connection. Wait a few minutes and try again.');
        return res.redirect('/forgot-password');
      }
      if (!smtpConfigured()) {
        /* Without SMTP there is nothing to send — say so plainly (this
         * reveals nothing about any account) and point at the backstop. */
        audit('system', 'auth.password_reset_requested',
          'A password reset was requested but email delivery (SMTP) is not configured on this instance; nothing was sent');
        flash(req, 'error', 'Email delivery is not configured on this instance, so reset links cannot be emailed. Contact platform support to receive a one-time reset link.');
        return res.redirect('/forgot-password');
      }

      /* CONSTANT RESPONSE from here on: the flash below is identical whether
       * the account exists, lacks a recovery email, or was emailed a link —
       * this form must not confirm which usernames exist. */
      const generic = () => {
        flash(req, 'ok', `If that account exists and has a recovery email on file, a reset link has been emailed to it. The link works exactly once and expires in ${RESET_TOKEN_TTL_MINUTES} minutes.`);
        return res.redirect('/login');
      };

      const username = String(req.body.username || '').trim();
      const u = username ? db.prepare('SELECT * FROM users WHERE username=?').get(username) : null;
      if (!u) {
        /* Like failed sign-ins, the submitted name is deliberately NOT
         * recorded: a pasted credential or password must never land in the
         * permanent, observer-visible audit log. */
        audit('system', 'auth.password_reset_requested',
          'Password reset requested for an unknown account (submitted name not recorded); nothing was sent');
        return generic();
      }
      if (!u.email) {
        audit('system', 'auth.password_reset_requested',
          `Password reset requested for account "${u.username}", which has no recovery email on file; nothing was sent. An administrator can add one under Accounts, or platform support can issue a one-time link.`);
        return generic();
      }

      const resetUrl = beginPasswordReset(u.id);
      try {
        await sendPasswordResetEmail({ to: u.email, displayName: u.display_name, resetUrl, ttlMinutes: RESET_TOKEN_TTL_MINUTES });
        audit('system', 'auth.password_reset_requested',
          `Password reset link emailed for account "${u.username}" (single use; token not recorded; expires in ${RESET_TOKEN_TTL_MINUTES} minutes)`);
      } catch (err) {
        /* Failed to send → void the token so no live link exists that nobody
         * received. Error detail stays out of the audit log (it can echo the
         * recipient address); the attempt itself is the loggable event. */
        clearResetToken(u.id);
        console.error('[recovery] reset email failed:', err.message);
        audit('system', 'auth.password_reset_email_failed',
          `Password reset email for account "${u.username}" could not be sent; the link was voided`);
      }
      return generic();
    } catch (err) { next(err); }
  });

  /* ---------------- reset password (consume the link) ------------------ */
  function rejectToken(res, check) {
    if (check.reason !== 'format') {
      audit('system', 'auth.password_reset_rejected', check.reason === 'expired'
        ? 'An expired password-reset link was opened (token not recorded)'
        : 'A password-reset link was opened that did not match any pending reset (token not recorded)');
    }
    return res.status(400).render('error', {
      title: 'Reset link not valid',
      message: check.reason === 'expired'
        ? 'This reset link has expired. Request a new one from the sign-in page, or ask platform support for a fresh link.'
        : 'This reset link is not valid or was already used. Request a new one from the sign-in page, or ask platform support for a fresh link.',
    });
  }

  router.get('/reset-password', (req, res) => {
    const check = findUserByValidResetToken(req.query.token);
    if (!check.ok) return rejectToken(res, check);
    res.render('reset-password', { title: 'Choose a new password', token: String(req.query.token).trim(), username: check.user.username });
  });

  router.post('/reset-password', (req, res) => {
    if (limiter.blocked(req)) {
      flash(req, 'error', 'Too many attempts from your connection. Wait a few minutes and try again.');
      return res.redirect('/login');
    }
    const token = String(req.body.token || '').trim();
    const check = findUserByValidResetToken(token);
    if (!check.ok) return rejectToken(res, check);

    const password = String(req.body.password || '');
    if (password.length < 10) {
      flash(req, 'error', 'Choose a password of at least 10 characters.');
      return res.redirect(`/reset-password?token=${encodeURIComponent(token)}`);
    }
    if (password !== String(req.body.password_confirm || '')) {
      flash(req, 'error', 'The two passwords did not match. Type the same new password in both fields.');
      return res.redirect(`/reset-password?token=${encodeURIComponent(token)}`);
    }

    /* Consume the token and set the new hash atomically: after this, the
     * link is void and only the bcrypt hash of the NEW password exists. */
    db.prepare('UPDATE users SET password_hash=?, reset_token_hash=NULL, reset_token_sent_at=NULL WHERE id=?')
      .run(bcrypt.hashSync(password, 12), check.user.id);
    audit('system', 'auth.password_reset_completed',
      `Account "${check.user.username}" set a new password via a single-use reset link; the link is now void`);
    flash(req, 'ok', 'Your password has been changed. Sign in with your new password.');
    res.redirect('/login');
  });

  return router;
};
