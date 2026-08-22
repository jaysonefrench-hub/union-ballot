/**
 * email-syntax.js — practical email-address syntax checking for the roster.
 *
 * SCOPE: syntax only. This is the cheap first gate that catches addresses
 * which could never receive mail as written (jane@gmail, jane@@x.com,
 * "jane smith@…"), so a typo does not sit on the roster as "Pending"
 * forever with a verification link that can never arrive. Whether the inbox
 * is real, reachable, and the member's own is proven by the existing
 * magic-link verification flow — never here.
 *
 * Deliberately NOT done (out of scope by design): MX/DNS lookups, SMTP
 * probing, disposable-domain blocklists, typo auto-correction.
 *
 * An EMPTY email is not an error anywhere in this system — it means the
 * member uses the paper-ballot path. Callers must not pass empty input here;
 * they decide the paper path first.
 */
'use strict';

/* Unquoted local part: RFC 5322 atext plus dot. Quoted local parts
 * ("jane smith"@x.com) are technically legal but rejected: on a union roster
 * they are far more likely a paste error than a real address. */
const LOCAL_RE = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/;

/* Domain label: letters/digits/hyphens, no leading/trailing hyphen (LDH). */
const LABEL_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i;

/* Final label (the TLD): letters only, at least 2 (.us … .museum), or an
 * internationalized punycode label (xn--…). Catches "jane@gmail" (TLD lost),
 * "jane@example.c" and "jane@example.123". */
const TLD_RE = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/i;

/**
 * Check one non-empty email address.
 * Returns { ok: true } or { ok: false, reason } where reason is plain
 * committee-readable language, safe to render next to the rejected row.
 */
function checkEmailSyntax(raw) {
  const email = String(raw);
  const fail = (reason) => ({ ok: false, reason });

  if (/\s/.test(email)) return fail('contains a space — email addresses cannot contain spaces');

  const atCount = (email.match(/@/g) || []).length;
  if (atCount === 0) return fail('missing the "@" sign');
  if (atCount > 1) return fail('has more than one "@" sign');

  const [local, domain] = email.split('@');
  if (!local) return fail('nothing before the "@" sign');
  if (!domain) return fail('nothing after the "@" sign — the domain is missing');
  if (email.length > 254 || local.length > 64) return fail('too long to be a deliverable address');

  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) {
    return fail('the part before the "@" starts or ends with a dot, or has two dots in a row');
  }
  if (!LOCAL_RE.test(local)) {
    return fail('the part before the "@" contains characters not allowed in an email address');
  }

  if (!domain.includes('.')) {
    return fail(`the domain "${domain}" has no ending — a deliverable address ends in .com, .org, .net, .us, …`);
  }
  const labels = domain.split('.');
  if (labels.some((l) => l === '')) {
    return fail('the domain has a stray dot (an empty section before, after, or between dots)');
  }
  for (const label of labels) {
    if (label.length > 63) return fail('a section of the domain is too long to be a real domain');
    if (!LABEL_RE.test(label)) {
      return fail(`the domain section "${label}" contains characters not allowed in a domain (or starts/ends with a hyphen)`);
    }
  }
  const tld = labels[labels.length - 1];
  if (!TLD_RE.test(tld)) {
    return fail(`the domain ending ".${tld}" is not a valid ending — it should be letters, like .com, .org or .us`);
  }

  return { ok: true };
}

module.exports = { checkEmailSyntax };
