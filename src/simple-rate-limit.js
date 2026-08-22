/**
 * simple-rate-limit.js — Minimal fixed-window per-IP limiter for low-volume
 * authentication endpoints (platform-owner sign-in, password-reset requests).
 * In-memory is sufficient for a single-instance deployment; nothing here is
 * persisted, and nothing links to any ballot. The voter-facing credential
 * limiter in routes/voter.js is separate and deliberately more generous.
 */
'use strict';

function makeRateLimiter({ windowMs, max }) {
  const hits = new Map(); // ip -> { count, resetAt }
  return {
    /** Count this request; true if the caller should refuse it. */
    blocked(req) {
      const now = Date.now();
      const ip = req.ip || 'unknown';
      let rec = hits.get(ip);
      if (!rec || now >= rec.resetAt) {
        rec = { count: 0, resetAt: now + windowMs };
        hits.set(ip, rec);
      }
      rec.count += 1;
      /* Opportunistic cleanup so the map cannot grow without bound. */
      if (hits.size > 5000) {
        for (const [k, v] of hits) { if (now >= v.resetAt) hits.delete(k); }
      }
      return rec.count > max;
    },
  };
}

module.exports = { makeRateLimiter };
