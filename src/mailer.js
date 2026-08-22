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

async function sendCredentialEmail({ to, memberName, electionTitle, credential, voteUrl, closesAt }) {
  if (!smtpConfigured()) throw new Error('SMTP not configured');
  const t = transporter();
  await t.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject: `Your secret-ballot voting credential — ${electionTitle}`,
    text:
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

— Election Committee`,
  });
}

/**
 * Email-address verification before electronic credential delivery.
 * The link carries a single-use, high-entropy token; the system stores only
 * its hash. Members on the paper-ballot path never receive (or need) this.
 */
async function sendVerificationEmail({ to, memberName, verifyUrl }) {
  if (!smtpConfigured()) throw new Error('SMTP not configured');
  const t = transporter();
  await t.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject: 'Confirm your email address for electronic voting',
    text:
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

— Election Committee`,
  });
}

module.exports = { smtpConfigured, sendCredentialEmail, sendVerificationEmail };
