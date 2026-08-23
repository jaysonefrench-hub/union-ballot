# Union Ballot

A self-hosted, secret-ballot electronic voting system for IAFF locals, built to the U.S. Department of Labor OLMS Compliance Tip *Electing Union Officers Using Remote Electronic Voting Systems* (updated December 2024) and the IAFF Legal Department's *Best Practices and Model Rules* guidance. It handles officer elections, delegate elections, dues and assessment votes, contract ratifications, bylaw amendments, and budget approvals, at local sizes from a dozen members to several thousand.

## The central guarantee

No one — including the administrator, the election committee, or anyone with a copy of the database — can learn how any member voted. This is architectural, not procedural:

Ballots are encrypted in the browser request the instant they are cast, using a sealed-box construction to the election's public key. The stored ballot row contains exactly three things: a random UUID, the election number, and ciphertext. No member ID, no credential reference, no timestamp, and (because the table is `WITHOUT ROWID` keyed on a random UUID) not even a physical insertion order. The matching decryption key is never stored anywhere: at election creation it is split with Shamir's Secret Sharing into N shares shown exactly once and handed to keyholders you choose — typically one representative per candidate slate plus a neutral. Reading even a single ballot requires K of those N people to act together at the tally ceremony, and even then the decrypted ballots carry no identity. What the committee *can* see is who has voted (the turnout list observers are traditionally entitled to compile) — never how.

Credentials are random 80-bit codes stored only as salted hashes; the plaintext exists only in the delivery email or the one-time export screen. Credential redemption is recorded by date only, so it cannot be correlated with any ballot. Every administrative action lands in a hash-chained, tamper-evident audit log that observers can verify live.

Source code: https://github.com/jaysonefrench-hub/union-ballot

## Quick start

Requires Node.js 18+.

```bash
git clone https://github.com/jaysonefrench-hub/union-ballot.git
cd union-ballot
npm install
npm run smoke     # optional: runs a full election end-to-end and verifies every guarantee
npm start         # http://localhost:3000
```

Visit `/setup` on first run to create the election-committee admin account. Add observer accounts (one per candidate) under Accounts. The voter-facing page is the root URL — voters never log in; they only enter their credential.

## Email verification before electronic credentials

Email addresses are format-checked at the door. When the committee imports the roster (`Name, email, member number` lines), every non-empty email is syntax-validated first — missing `@`, missing `.com`/`.org`-style ending, spaces, `@@`, stray dots, and similar garbage are caught immediately. Valid rows import as usual; rejected rows are **not** imported and come back on an import report listing line number, name, address, and the exact problem, with the bad rows pre-filled in a fix-and-re-import form. Nothing is silently skipped and one typo never fails the whole upload. A blank email is not an error — that member simply uses the paper-ballot method. The same check runs when editing a member's email on the roster page. (Syntax only, by design: no MX/DNS lookups, no SMTP probing, no blocklists — proving the inbox is real and the member's own remains the job of the verification flow below.)

A voting credential is only as trustworthy as the address it is sent to. Every member added to the roster with an email address starts **unverified**: the system emails them a single-use, expiring confirmation link (stored only as a hash — the same discipline as credentials), and only after the member clicks it is the address marked verified. Electronic credentials **cannot be issued while any electronic-path member remains unverified** — the committee gets a clear error naming the pending members, with the choice to resend their links or flag them for paper. The roster page shows Verified / Pending per member with a resend button; if SMTP is not configured, the resend button instead displays a one-time link for manual delivery. Changing a member's email resets their verification. None of this touches the paper-ballot path: members without email, or flagged for paper, never need to verify anything.

**DEMO / TEST dry-run (how to turn it on).** To run a full committee dry-run without real SMTP or magic-link confirms, create a vote and check **This is a test election**. Newly created test elections turn on `demo_skip_email_verify` automatically: members with a syntactically valid email can receive electronic credentials even if `email_verified` is still 0. Binding elections (`is_test=0`) can never set or honor that flag — a production vote on the same instance (for example Greensboro) stays gated. If a TEST election already exists from before this feature, open it in the committee UI and use the **Skip email verification (DEMO dry-run)** toggle (audit-logged). Do **not** set a global `DEMO=1` environment variable on a production instance; that is only for a public demonstration site and is unrelated to this election-level flag.

## Jurisdiction gates — Florida PERC contract ratification

Election creation now records the **jurisdiction** (state) of the bargaining unit. For a **binding electronic contract-ratification vote in Florida**, the system is a hard stop: Fla. Admin. Code 60CC-4.002 requires ratification by secret ballot at a meeting or by mail with a publicly announced count, Florida PERC has denied electronic-ratification requests (May 2022), and no general PERC approval of electronic ratification exists. Creation (and, defense-in-depth, credential issuance and opening) is blocked unless the committee explicitly checks that the unit holds a **current PERC variance for electronic ratification** — that acknowledgment is the committee's own recorded claim, stored on the election and in the audit log; the system never verifies or implies PERC or OLMS approval. Florida officer elections, bylaws amendments, other non-ratification votes, test elections, and every non-Florida jurisdiction are unaffected. See `COMPLIANCE.md` for the full note.

## Platform owner page — aggregate stats & recovery (`/platform`)

For the operator who hosts the instance (not the committee, not observers). Set **`PLATFORM_OWNER_KEY`** to a strong secret — at least 16 characters, ideally `openssl rand -hex 32` — and `/platform` comes alive; leave it unset and the page 404s as if it did not exist. Access requires the key itself, entered on the page's own sign-in form (which sets a session flag only — the key is never stored, logged, or audited) or sent as an `X-Platform-Key` request header for scripted checks; keys are compared in constant time, and a committee or observer session grants **nothing** here, deliberately.

The page shows **aggregate counts only**, fit to show a sponsor: elections by status (completed/tallied vs draft, credentials issued, open, closed), test vs binding, sealed ballots stored and counted, paper ballots recorded, overall and average turnout rates where an eligibility snapshot exists, and roster size as a single number. No names, no emails, no phone numbers, no member lists, no local contact info. This instance serves one local today; the metrics are shaped so future multi-local deployments can roll up into the same report.

The same page lists the sealed records archives (below) with downloads, and can generate a one-time committee password-reset link (below) — the two recovery powers a platform owner actually needs, neither of which can open a ballot.

## Sealed records archives on tally

The moment a vote is tallied, the system automatically persists its records archive under `DATA_DIR/archives/` — the same contents as the manual **Export records archive** button (election configuration, eligibility snapshot, turnout, hashed credentials, **encrypted** ballots, aggregate results, audit log). If `BACKUP_KEY` is configured the archive file is encrypted at rest with AES-256-GCM in the same format as database backups, so `scripts/decrypt-backup.js` opens both; without it, the archive is plain JSON and the audit log says so. Either way the archive can never open a ballot: the ballots inside are still sealed to the election key that exists only as the keyholders' shares.

This is the retention safety net and the recovery path: a local that loses its login, its laptop, or its download can be handed its results back from the platform page's archive list (election, title, tallied at, ballot count, download) — without anyone decrypting anything.

## Committee password recovery — never a plaintext password

Passwords are stored only as bcrypt hashes, so there is nothing to "look up" — recovery always means the account holder **chooses a new password** through a single-use reset link whose token is stored hash-only (the same discipline as email-verification links), expires (default 60 minutes, `RESET_TOKEN_TTL_MINUTES`), and dies on first use. Two ways to get one: **self-service** — the sign-in page links to `/forgot-password`, which emails a reset link if SMTP is configured and the account has a recovery email on file (set one per account under **Accounts**; the response never reveals whether a username exists); or **platform owner** — with `PLATFORM_OWNER_KEY`, generate a one-time link on `/platform` and deliver it out-of-band after verifying who is asking. Requests, completions, and rejected links are audit-logged; tokens and passwords never are.

## Configuration (environment variables)

`PORT` — listen port (default 3000). `BASE_URL` — the public https URL, used in credential, verification, and password-reset emails. `VERIFY_TOKEN_TTL_DAYS` — how long an email-verification link stays valid (default 14). `RESET_TOKEN_TTL_MINUTES` — how long a password-reset link stays valid (default 60). `DATA_DIR` — where the SQLite database (and `archives/`) lives (default `./data`). `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `MAIL_FROM` — email delivery of credentials; if unset, credentials are shown once for mail-merge delivery instead. `REISSUE_KEY` — optional 64-hex-char key for the encrypted member↔credential map used only to void-and-reissue lost credentials (auto-generated if unset). `BACKUP_KEY` — 64-hex-char key that encrypts downloadable database backups and the automatic records archives at rest; keep it off the server and separate from `REISSUE_KEY`. `PLATFORM_OWNER_KEY` — strong secret (16+ characters) that enables the `/platform` owner page; unset = page disabled. `NODE_ENV=production` — enables secure cookies (requires HTTPS).

## Hosted URLs

- **union-ballot.com** — marketing landing (`www/`, Netlify). Apex stays on this site; do not point it at Render.
- **vote.union-ballot.com** — voting app (Render).

## Production deployment

Run behind HTTPS — this is non-negotiable for a real election. The simplest defensible setup is a small VPS with Caddy or nginx terminating TLS in front of `node server.js` under systemd, with `NODE_ENV=production` and `BASE_URL` set. Back up the `data` directory; it contains only hashed credentials and encrypted ballots, but it *is* the election record you must retain for one year. Record the exact commit hash of the deployed code (`git rev-parse HEAD`) in your election records so the retained source matches what actually ran. The key shares are the one thing that cannot be recovered: if fewer than the threshold number survive, the ballots can never be opened and the election must be rerun, so treat share custody as seriously as a physical ballot box key.

## Running an election

The workflow the app enforces: create the vote (for officer, delegate, and dues votes it requires you to record IAFF Legal Department approval of the platform and procedures, per the IAFF Best Practices and Model Rules) → the key ceremony displays the decryption shares exactly once for distribution to keyholders → issue credentials (eligibility is frozen from the roster at that moment; electronic credentials go only to verified email addresses, and members without email or who opt for paper are listed for the alternative method) → open voting → close voting → tally ceremony with K keyholders and observers present → publish results and export the records archive.

Run a **test election** first. Mark it as a test at creation, let candidate observers cast practice ballots and watch the tally — OLMS explicitly views observable test runs favorably, and it builds member confidence.

See `COMPLIANCE.md` for the requirement-by-requirement mapping to the LMRDA/OLMS guidance and the IAFF model rules, plus the procedural checklist of obligations that software cannot satisfy for you.

## What this system deliberately does not do

It never shows a voter their recorded choices after casting (an echo screen becomes a coercion tool), it never logs ballot events with identity, it never stores credential plaintext, and it never stores the election private key. There is no "admin override" to open ballots — that absence is the feature.
