/**
 * scripts/mailer-mime-test.js — Regression for MIME transfer-encoding of
 * magic-link URLs. Nodemailer's default quoted-printable encoding turns
 * `?token=<hex>` into `?token=3D<hex>` and soft-wraps the line at column 76,
 * which is what produced the unclickable verification link in Gmail.
 *
 * This test composes the real verification and password-reset messages with
 * the production BASE_URL length and a full 32-char token, then asserts the
 * literal `token=` + exact token survives in the on-the-wire MIME. It fails
 * on the pre-fix mailer (which passed a plain `text:` string to nodemailer)
 * and passes once the parts are emitted as 8bit.
 */
'use strict';

const assert = require('assert');
const { generateVerifyToken } = require('../src/crypto');
const {
  buildVerificationEmail,
  buildPasswordResetEmail,
  buildCredentialEmail,
  renderMail,
} = require('../src/mailer');

const PROD_BASE = 'https://vote.union-ballot.com';
/* Longer than production, still well under SMTP's 998-char line limit.
 * Forces the wrap boundary past column 76 even if BASE_URL shrinks. */
const LONG_BASE = 'https://very-long-preview-host.vote.union-ballot.com';

async function assertTokenIntact(label, raw, token) {
  const needle = `token=${token}`;
  assert.ok(
    raw.includes(needle),
    `${label}: rendered MIME must contain literal ${JSON.stringify(needle)} (quoted-printable would emit token=3D… and fail this check)`
  );
  assert.ok(
    !raw.includes(`token=3D${token}`) && !/token=3D[0-9a-f]{8}/i.test(raw),
    `${label}: rendered MIME must not quoted-printable-escape the token '='`
  );
}

async function assertLinkMail({ label, build, base, token }) {
  const url = `${base}/${label === 'password-reset' ? 'reset-password' : 'verify-email'}?token=${token}`;
  const mail = build({
    to: 'member@gmail.com',
    memberName: 'Jane Doe',
    displayName: 'Jane Doe',
    verifyUrl: url,
    resetUrl: url,
    ttlMinutes: 60,
  });
  const raw = await renderMail(mail);
  await assertTokenIntact(label + ' text', raw, token);
  const href = `href="${url}"`;
  assert.ok(raw.includes(href), `${label}: HTML alternative must carry an unwrapped <a ${href}>`);
  assert.ok(
    /Content-Transfer-Encoding:\s*8bit/i.test(raw),
    `${label}: textual parts must be 8bit so QP never touches the URL`
  );
  return raw;
}

(async () => {
  process.env.MAIL_FROM = process.env.MAIL_FROM || 'ballots@union-ballot.com';

  const token = generateVerifyToken();
  assert.strictEqual(token.length, 32, 'generateVerifyToken still returns 32 hex chars');
  assert.ok(/^[0-9a-f]{32}$/.test(token), 'token is lowercase hex');

  /* Production length — the live NC host. */
  await assertLinkMail({
    label: 'verification',
    build: buildVerificationEmail,
    base: PROD_BASE,
    token,
  });
  await assertLinkMail({
    label: 'password-reset',
    build: buildPasswordResetEmail,
    base: PROD_BASE,
    token,
  });

  /* Longer host: still intact, still 8bit. */
  const longToken = generateVerifyToken();
  await assertLinkMail({
    label: 'verification',
    build: buildVerificationEmail,
    base: LONG_BASE,
    token: longToken,
  });
  await assertLinkMail({
    label: 'password-reset',
    build: buildPasswordResetEmail,
    base: LONG_BASE,
    token: longToken,
  });

  /* Credential mail: voteUrl has no query string today, but the same 8bit
   * path must keep whatever URL we pass, including a future `?token=`. */
  const voteToken = generateVerifyToken();
  const voteUrl = `${LONG_BASE}/?token=${voteToken}`;
  const credRaw = await renderMail(buildCredentialEmail({
    to: 'member@gmail.com',
    memberName: 'Jane Doe',
    electionTitle: '2026 Officer Election',
    credential: 'ABCD-EFGH-IJKL-MNOP',
    voteUrl,
    closesAt: 'Friday noon',
  }));
  await assertTokenIntact('credential', credRaw, voteToken);
  assert.ok(credRaw.includes(`href="${voteUrl}"`), 'credential HTML links the vote URL');

  /* Control: the pre-fix composition (plain `text:` string, nodemailer
   * defaults) must NOT satisfy the intact-token check. If this control
   * starts passing, nodemailer changed and the 8bit workaround may be
   * unnecessary — but the assertions above remain the contract. */
  const controlUrl = `${PROD_BASE}/verify-email?token=${token}`;
  const controlRaw = await renderMail({
    from: process.env.MAIL_FROM,
    to: 'member@gmail.com',
    subject: 'Confirm your email address for electronic voting',
    text:
`Jane Doe,

Confirm your email address by opening this link:

    ${controlUrl}

If you did not expect this — or you prefer a paper ballot — reply.`,
  });
  assert.ok(
    !controlRaw.includes(`token=${token}`),
    'control: default nodemailer quoted-printable still mangles token= (test would be a no-op if this passed)'
  );
  assert.ok(
    controlRaw.includes('token=3D') || /Content-Transfer-Encoding:\s*quoted-printable/i.test(controlRaw),
    'control: default composition is quoted-printable'
  );

  console.log('MAILER MIME TESTS PASSED ✔');
  console.log('  Verification and password-reset links keep literal token=<hex> on the wire');
  console.log('  (production and longer BASE_URL); HTML <a href> matches; 8bit CTE.');
  console.log('  Control confirms default nodemailer QP still fails the same check.');
})().catch((e) => {
  console.error('MAILER MIME TEST FAILED:', e);
  process.exit(1);
});
