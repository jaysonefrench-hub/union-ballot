/**
 * election-demo.js — TEST-election DEMO helpers.
 *
 * Binding elections (is_test=0) can never skip magic-link email verification.
 * The bypass lives on the election row (`demo_skip_email_verify`), not in a
 * process-wide env var, so a production instance that also hosts a dry-run
 * cannot accidentally leave a binding vote (e.g. Greensboro) in demo mode.
 */
'use strict';

function isTestElection(e) {
  return !!(e && Number(e.is_test) === 1);
}

/** True only when this election is a TEST vote AND the committee flag is on. */
function electionSkipsEmailVerify(e) {
  return isTestElection(e) && Number(e.demo_skip_email_verify) === 1;
}

function markTestElectionBanner(res, e) {
  if (isTestElection(e)) res.locals.electionIsTest = true;
}

/**
 * New TEST elections default the bypass ON. An explicit posted `0` opts out
 * (so the committee can still practice the magic-link flow on a test vote).
 * Binding creates always return 0, even if the form field is posted.
 */
function demoSkipForCreate({ isTest, posted }) {
  if (!isTest) return 0;
  let v = posted;
  if (Array.isArray(v)) v = v[v.length - 1];
  if (v === undefined || v === null || v === '') return 1;
  return v === '1' ? 1 : 0;
}

module.exports = {
  isTestElection,
  electionSkipsEmailVerify,
  markTestElectionBanner,
  demoSkipForCreate,
};
