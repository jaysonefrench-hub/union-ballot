/**
 * src/roster-csv.js — the downloadable roster CSV template and the tolerant
 * row parser the importer runs on whatever comes back.
 *
 * The two halves live in one file on purpose: the parser must always accept
 * the exact template this module serves, including every quirk Excel or
 * Google Sheets adds on the round trip (UTF-8 BOM, CRLF line endings, quoted
 * fields with embedded commas, all-empty padding rows, trailing blank lines).
 *
 * The template is static text: it carries NO member data, ever. It is still
 * served only inside a committee session (/admin), like every roster page.
 */
'use strict';

const TEMPLATE_FILENAME = 'roster-template.csv';

/* Header row first, then clearly fake example rows (example.com addresses).
 * The blank email on the second example is deliberate: it shows the
 * paper-ballot case, which is a valid row, not an error. CRLF endings are
 * the CSV convention Excel expects. */
const TEMPLATE_ROWS = [
  ['Name', 'Email', 'Member number'],
  ['Jane Example', 'jane@example.com', '1001'],
  ['Bob Example', '', '1002'],
  ['Maria Example', 'maria@example.com', '1003'],
];

const TEMPLATE_CSV = TEMPLATE_ROWS.map((r) => r.join(',')).join('\r\n') + '\r\n';

/** Split one CSV line into trimmed fields, honoring double-quoted fields
 * (embedded commas stay inside the field; "" inside quotes is a literal "). */
function parseCsvLine(line) {
  const fields = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; } else inQuotes = false;
      } else cur += ch;
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      fields.push(cur); cur = '';
    } else cur += ch;
  }
  fields.push(cur);
  return fields.map((f) => f.trim());
}

/** True for the template's header row (any casing, "email"/"e-mail").
 * No real member can match: a member literally named "Name" would need the
 * literal email "email", which the syntax gate would reject anyway. */
function isHeaderRow(fields) {
  const first = (fields[0] || '').toLowerCase();
  const second = (fields[1] || '').toLowerCase().replace(/[^a-z]/g, '');
  return first === 'name' && (second === 'email' || second === 'emailaddress');
}

/**
 * Parse pasted or uploaded roster text into candidate rows.
 * Returns [{ line, raw, name, email, num }] with 1-based original line
 * numbers so the import report can point at the exact row. Skipped (never
 * reported, because they are not data): a leading BOM, the header row,
 * blank lines, and rows whose every field is empty (",," Excel padding).
 * Validation (missing name, email syntax) stays the caller's job.
 */
function parseRosterText(text) {
  const rows = [];
  const lines = String(text || '').replace(/^\uFEFF/, '').split(/\r\n|\r|\n/);
  lines.forEach((rawLine, idx) => {
    const line = rawLine.trim();
    if (!line) return;
    const fields = parseCsvLine(line);
    if (isHeaderRow(fields)) return;
    if (fields.every((f) => !f)) return;
    const [name, email, num] = fields;
    rows.push({ line: idx + 1, raw: line, name: name || '', email: email || '', num: num || '' });
  });
  return rows;
}

module.exports = { TEMPLATE_FILENAME, TEMPLATE_CSV, parseRosterText };
