/**
 * mailer.js — Credential delivery by email (nodemailer/SMTP).
 *
 * Configure via environment variables:
 *   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, MAIL_FROM
 *
 * If SMTP is not configured, sendCredentialEmail() throws and the admin UI
 * falls back to offering a one-time mail-merge export instead.
 *
 * PRIVACY NOTE: the email necessarily contains the member's credential in
 * transit. The system itself stores only the salted hash. Locals should use
 * a mail provider they control and remind members to delete the email after
 * voting. This mirrors OLMS-reviewed vendor practice (credentials mailed or
 * emailed to members after eligibility is determined).
 *
 * MIME / LINK INTEGRITY
 * ---------------------
 * Nodemailer will quoted-printable-encode a text/plain part whenever the
 * body is not 7-bit ASCII *or* any line is longer than 76 characters. Both
 * are true of these messages: they contain typographic em-dashes, and a
 * production verification URL (`https://vote.union-ballot.com/verify-email
 * ?token=` + 32 hex chars, indented 4 spaces) is 85 characters.
 *
 * Quoted-printable then:
 *   1. Escapes every literal `=` as `=3D`
 *   2. Soft-wraps at 76 columns by inserting `=\r\n`
 *
 * The wire form of the link becomes `...?token=3D<first-20-hex>=\r\n<rest>`,
 * which some clients (Gmail's autolinker in particular) surface as a
 * missing or mangled `=` after `token`. The same shape affects password-
 * reset links. Nodemailer's public `encoding: '7bit'` / `'8bit'` option
 * does NOT prevent this: MimeNode.getTransferEncoding() treats any CTE
 * other than `base64` / `quoted-printable` as unset and re-selects QP.
 *
 * The parts below are therefore emitted as raw `8bit` MIME (valid: bodies
 * are UTF-8, longest line ≪ SMTP's 998-char limit) so the URL bytes are
 * never escaped or wrapped. An HTML alternative with a real <a href>
 * is sent alongside so a client that only follows anchors still gets an
 * unwrapped link.
 */
'use strict';

const nodemailer = require('nodemailer');

function smtpConfigured() {
  return !!(process.env.SMTP_HOST && process.env.MAIL_FROM);
}

function transporter() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: process.env.SMTP_USER
      ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
      : undefined,
  });
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Emit a textual MIME part with Content-Transfer-Encoding: 8bit, bypassing
 * nodemailer's quoted-printable rewriter. See the file header.
 */
function eightBitPart(contentType, body) {
  const crlf = String(body).replace(/\r\n/g, '\n').replace(/\n/g, '\r\n');
  return {
    raw:
      `Content-Type: ${contentType}; charset=utf-8\r\n` +
      `Content-Transfer-Encoding: 8bit\r\n` +
      `\r\n` +
      crlf,
  };
}

/** Same wording as the plain-text body, with each URL as a real <a href>. */
function htmlAlternative(text, urls) {
  let html = escapeHtml(text);
  for (const url of urls) {
    if (!url) continue;
    const safe = escapeHtml(url);
    html = html.split(safe).join(`<a href="${safe}">${safe}</a>`);
  }
  return `<!DOCTYPE html>\n<html><body>\n${html.replace(/\n/g, '<br>\n')}\n</body></html>\n`;
}

function mailFrom() {
  return process.env.MAIL_FROM || 'noreply@localhost';
}

function buildCredentialEmail({ to, memberName, electionTitle, credential, voteUrl, closesAt }) {
  const text =
`${memberName},

You are eligible to vote in: ${electionTitle}

Your one-time voting credential:

    ${credential}

How to vote:
1. Go to: ${voteUrl}
2. Enter the credential above. Do NOT enter your name anywhere — the ballot is secret and the system stores no link between you and your choices.
3. Make your selections and press "Cast ballot".

Voting closes: ${closesAt || 'see election notice'}.

Keep this credential private. It can be used only once. If you lose it, contact the election committee for a replacement (your old one will be voided).
For ballot secrecy, delete this email after you vote.

— Election Committee`;
  return {
    from: mailFrom(),
    to,
    subject: `Your secret-ballot voting credential — ${electionTitle}`,
    text: eightBitPart('text/plain', text),
    html: eightBitPart('text/html', htmlAlternative(text, [voteUrl])),
  };
}

function buildVerificationEmail({ to, memberName, verifyUrl }) {
  const text =
`${memberName},

Your local's election committee added this email address to the voter roster
for ELECTRONIC ballot delivery. Before any voting credential can be sent to
this address, you must confirm that it is yours and that it works.

Confirm your email address by opening this link:

    ${verifyUrl}

The link works exactly once and expires. If it has expired, ask the election
committee to resend it.

If you did not expect this — or you prefer a paper ballot — reply to the
election committee. Members who do not confirm an email address are provided
the alternative paper-ballot method instead; confirming is only required for
electronic ballot delivery.

— Election Committee`;
  return {
    from: mailFrom(),
    to,
    subject: 'Confirm your email address for electronic voting',
    text: eightBitPart('text/plain', text),
    html: eightBitPart('text/html', htmlAlternative(text, [verifyUrl])),
  };
}

function buildPasswordResetEmail({ to, displayName, resetUrl, ttlMinutes }) {
  const text =
`${displayName},

A password reset was requested for your election-committee account.

Choose a new password by opening this link:

    ${resetUrl}

The link works exactly once and expires in ${ttlMinutes} minutes. Your
password is never emailed or displayed — you will set a new one of your own
choosing on that page.

If you did not request this, you can ignore this email: your current
password still works and nothing has changed. The request has been recorded
in the tamper-evident audit log either way.

— Election system`;
  return {
    from: mailFrom(),
    to,
    subject: 'Reset your election-committee account password',
    text: eightBitPart('text/plain', text),
    html: eightBitPart('text/html', htmlAlternative(text, [resetUrl])),
  };
}

/**
 * Compose a message to its on-the-wire MIME form without sending.
 * Used by the mailer regression test; also handy for local inspection.
 */
async function renderMail(mail) {
  const t = nodemailer.createTransport({
    streamTransport: true,
    buffer: true,
    newline: 'unix',
  });
  const info = await t.sendMail(mail);
  return Buffer.isBuffer(info.message) ? info.message.toString('utf8') : String(info.message);
}

async function sendMail(mail) {
  if (!smtpConfigured()) throw new Error('SMTP not configured');
  await transporter().sendMail(mail);
}

async function sendCredentialEmail(opts) {
  await sendMail(buildCredentialEmail(opts));
}

async function sendVerificationEmail(opts) {
  await sendMail(buildVerificationEmail(opts));
}

async function sendPasswordResetEmail(opts) {
  await sendMail(buildPasswordResetEmail(opts));
}

module.exports = {
  smtpConfigured,
  sendCredentialEmail,
  sendVerificationEmail,
  sendPasswordResetEmail,
  buildCredentialEmail,
  buildVerificationEmail,
  buildPasswordResetEmail,
  renderMail,
};
