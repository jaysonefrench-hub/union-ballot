# Union Ballot

A self-hosted, secret-ballot electronic voting system for IAFF locals, built to the U.S. Department of Labor OLMS Compliance Tip *Electing Union Officers Using Remote Electronic Voting Systems* (updated December 2024) and the IAFF Legal Department's *Best Practices and Model Rules* guidance. It handles officer elections, delegate elections, dues and assessment votes, contract ratifications, bylaw amendments, and budget approvals, at local sizes from a dozen members to several thousand — and one deployment hosts **many locals at once**, each a fully walled-off tenant (see "Locals" below).

## The central guarantee

No one — including the administrator, the election committee, or anyone with a copy of the database — can learn how any member voted. This holds **per local** exactly as it held when one instance served one local: hosting many locals adds isolation between them, never a new path to any ballot. This is architectural, not procedural:

Ballots are encrypted in the browser request the instant they are cast, using a sealed-box construction to the election's public key. The stored ballot row contains exactly three things: a random UUID, the election number, and ciphertext. No member ID, no credential reference, no timestamp, and (because the table is `WITHOUT ROWID` keyed on a random UUID) not even a physical insertion order. The matching decryption key is never stored anywhere: at election creation it is split with Shamir's Secret Sharing into N shares shown exactly once and handed to keyholders you choose — typically one representative per candidate slate plus a neutral. Reading even a single ballot requires K of those N people to act together at the tally ceremony, and even then the decrypted ballots carry no identity. What the committee *can* see is who has voted (the turnout list observers are traditionally entitled to compile) — never how.

Credentials are random 80-bit codes stored only as salted hashes; the plaintext exists only in the delivery email or the one-time export screen. Credential redemption is recorded by date only, so it cannot be correlated with any ballot. Every administrative action lands in a hash-chained, tamper-evident audit log that observers can verify live.

Source code: https://github.com/jaysonefrench-hub/union-ballot

## Quick start

Requires Node.js 18+.

```bash
git clone https://github.com/jaysonefrench-hub/union-ballot.git
cd union-ballot
npm install
npm run smoke     # optional: runs full elections end-to-end (two locals) and verifies every guarantee
npm start         # http://localhost:3000
```

Visit `/platform/setup` on first run to create the **platform administrator** account, then from `/platform` create your first **local** — that flow provisions the local's first election-committee admin account in the same step. The committee signs in at `/login`, adds observer accounts (one per candidate) under Accounts, and runs its elections. The voter-facing page is the root URL — voters never log in; they only enter their credential.

## Locals — one platform, many walled-off tenants

A **local** is the unit of tenancy: it has a name, an optional local number, and a state/jurisdiction. Every roster member, election (with its races, candidates, credentials, sealed ballots, and turnout), committee/observer account, audit-log entry, and records archive belongs to exactly one local, and the scoping is enforced in the queries themselves (`src/tenant.js`), not just hidden in the UI: an account signed in for Local A is structurally incapable of reading or writing Local B's roster, elections, accounts, credentials, or archives, no matter what id it guesses or URL it types — another local's id renders exactly like an id that never existed. Every committee/observer page names the local it is managing in the header, since the same person may hold accounts at more than one local.

The audit log is hash-chained **per local**: each entry commits to the previous entry of the same local, so a local's observers verify their complete chain without ever seeing another local's entries. (Voter-portal events that match no election — rejected credentials, rate limits — are anonymous by design and recorded on the platform's own chain, which every local's observer page surfaces as instance-wide security events.) Databases created before multi-tenancy are migrated automatically at startup: one default local is created — named from what the data says (a "Local NNN" pattern in election titles, the instance's `BRAND_LOCAL`/`BRAND_ORG`, or the most recent election's jurisdiction) — and every existing row is assigned to it, so the pre-existing committee login and its data keep working unchanged, and the old instance-wide audit chain verifies untouched as that local's chain.

Voters never pick a local: the credential itself is the scope. A credential matches exactly one election, which belongs to exactly one local, so a voter can only ever open the ballot their credential was issued for.

## Email verification before electronic credentials

Email addresses are format-checked at the door. When the committee imports the roster (`Name, email, member number` lines), every non-empty email is syntax-validated first — missing `@`, missing `.com`/`.org`-style ending, spaces, `@@`, stray dots, and similar garbage are caught immediately. Valid rows import as usual; rejected rows are **not** imported and come back on an import report listing line number, name, address, and the exact problem, with the bad rows pre-filled in a fix-and-re-import form. Nothing is silently skipped and one typo never fails the whole upload. A blank email is not an error — that member simply uses the paper-ballot method. The same check runs when editing a member's email on the roster page. (Syntax only, by design: no MX/DNS lookups, no SMTP probing, no blocklists — proving the inbox is real and the member's own remains the job of the verification flow below.)

A voting credential is only as trustworthy as the address it is sent to. Every member added to the roster with an email address starts **unverified**: the system emails them a single-use, expiring confirmation link (stored only as a hash — the same discipline as credentials), and only after the member clicks it is the address marked verified. Electronic credentials **cannot be issued while any electronic-path member remains unverified** — the committee gets a clear error naming the pending members, with the choice to resend their links or flag them for paper. The roster page shows Verified / Pending per member with a resend button; if SMTP is not configured, the resend button instead displays a one-time link for manual delivery. Changing a member's email resets their verification. None of this touches the paper-ballot path: members without email, or flagged for paper, never need to verify anything.

**DEMO / TEST dry-run (how to turn it on).** To run a full committee dry-run without real SMTP or magic-link confirms, create a vote and check **This is a test election**. Newly created test elections turn on `demo_skip_email_verify` automatically: members with a syntactically valid email can receive electronic credentials even if `email_verified` is still 0. Binding elections (`is_test=0`) can never set or honor that flag — a production vote on the same instance (for example Greensboro) stays gated. If a TEST election already exists from before this feature, open it in the committee UI and use the **Skip email verification (DEMO dry-run)** toggle (audit-logged). Do **not** set a global `DEMO=1` environment variable on a production instance; that is only for a public demonstration site and is unrelated to this election-level flag.

## Jurisdiction gates — Florida PERC contract ratification

Election creation now records the **jurisdiction** (state) of the bargaining unit. For a **binding electronic contract-ratification vote in Florida**, the system is a hard stop: Fla. Admin. Code 60CC-4.002 requires ratification by secret ballot at a meeting or by mail with a publicly announced count, Florida PERC has denied electronic-ratification requests (May 2022), and no general PERC approval of electronic ratification exists. Creation (and, defense-in-depth, credential issuance and opening) is blocked unless the committee explicitly checks that the unit holds a **current PERC variance for electronic ratification** — that acknowledgment is the committee's own recorded claim, stored on the election and in the audit log; the system never verifies or implies PERC or OLMS approval. Florida officer elections, bylaws amendments, other non-ratification votes, test elections, and every non-Florida jurisdiction are unaffected. See `COMPLIANCE.md` for the full note.

## Platform administrator — aggregate stats, local creation & recovery (`/platform`)

For the operator who hosts the instance for many locals (not any committee, not observers). This is a real, ongoing operational role with its own **accounts** (`platform_users`, bcrypt-hashed passwords, its own sign-in at `/platform`) — a committee or observer session grants **nothing** here, deliberately, and a platform session grants nothing under `/admin` or `/observe`.

**Bootstrapping the first platform administrator.** Visit `/platform/setup`:
- If **`PLATFORM_OWNER_KEY`** is configured (16+ characters, ideally `openssl rand -hex 32`) — which every pre-multi-tenant deployment already has — the form requires that key: whoever holds the old key claims the new role. The key's only remaining job is authorizing `/platform/setup`; it no longer opens any stats page by itself. It doubles as break-glass recovery: if every platform password is lost, rotate the env var and create a replacement account there (loudly audit-logged).
- If the key is unset, open first-run creation is allowed only while the database is **completely empty** — the same trust model as the old committee `/setup`, where the person deploying the instance claims it immediately. On a database that already holds data, setup refuses and instructs you to set the env var first, so nobody can stumble onto a live instance and claim the platform role.

The dashboard shows **aggregate counts only**, fit to show a sponsor — **per local, plus an all-locals rollup**: elections by status (completed/tallied vs draft, credentials issued, open, closed), test vs binding, credentials issued/redeemed/voided, sealed ballots stored and counted, paper ballots recorded, overall and average turnout rates where an eligibility snapshot exists, and roster sizes as single numbers. No names, no emails, no phone numbers, no member lists, no local contact info — the same boundary the old single-local platform page kept, extended across many locals.

From the same page the platform administrator **creates a new local**, provisioning that local's very first committee-admin account in the same transaction (the multi-local heir to the old one-time `/setup`); the account is born inside the new local and the flow can never grant access to an existing one. The page also lists the sealed records archives (below) with downloads, generates one-time committee password-reset links (below — the confirmation page names the account's local), and downloads the encrypted whole-database backup (which spans every local and is therefore an operator function, not a committee one). None of these powers can open a ballot: archives and backups hold ciphertext sealed to keyholder shares that are never stored, and there is deliberately no platform route that reads a roster or writes to any local's elections.

## Sealed records archives on tally

The moment a vote is tallied, the system automatically persists its records archive under `DATA_DIR/archives/` — the same contents as the manual **Export records archive** button (election configuration, eligibility snapshot, turnout, hashed credentials, **encrypted** ballots, aggregate results, audit log). If `BACKUP_KEY` is configured the archive file is encrypted at rest with AES-256-GCM in the same format as database backups, so `scripts/decrypt-backup.js` opens both; without it, the archive is plain JSON and the audit log says so. Either way the archive can never open a ballot: the ballots inside are still sealed to the election key that exists only as the keyholders' shares.

This is the retention safety net and the recovery path: a local that loses its login, its laptop, or its download can be handed its results back from the platform archive list (local, election, title, tallied at, ballot count, download) — without anyone decrypting anything. The archive's audit log is the owning local's own chain, never another local's entries.

## Committee password recovery — never a plaintext password

Passwords are stored only as bcrypt hashes, so there is nothing to "look up" — recovery always means the account holder **chooses a new password** through a single-use reset link whose token is stored hash-only (the same discipline as email-verification links), expires (default 60 minutes, `RESET_TOKEN_TTL_MINUTES`), and dies on first use. Two ways to get one: **self-service** — the sign-in page links to `/forgot-password`, which emails a reset link if SMTP is configured and the account has a recovery email on file (set one per account under **Accounts**; the response never reveals whether a username exists); or **platform administrator** — generate a one-time link on `/platform` (the confirmation page names the account's local, so support can check it is helping the right one) and deliver it out-of-band after verifying who is asking. Requests, completions, and rejected links are audit-logged on the account's local chain; tokens and passwords never are.

## Configuration (environment variables)

`PORT` — listen port (default 3000). `BASE_URL` — the public https URL, used in credential, verification, and password-reset emails. `VERIFY_TOKEN_TTL_DAYS` — how long an email-verification link stays valid (default 14). `RESET_TOKEN_TTL_MINUTES` — how long a password-reset link stays valid (default 60). `DATA_DIR` — where the SQLite database (and `archives/`) lives (default `./data`). `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `MAIL_FROM` — email delivery of credentials; if unset, credentials are shown once for mail-merge delivery instead. `REISSUE_KEY` — optional 64-hex-char key for the encrypted member↔credential map used only to void-and-reissue lost credentials (auto-generated if unset). `BACKUP_KEY` — 64-hex-char key that encrypts downloadable database backups and the automatic records archives at rest; keep it off the server and separate from `REISSUE_KEY`. `PLATFORM_OWNER_KEY` — strong secret (16+ characters) that authorizes creating a platform-administrator account at `/platform/setup` (bootstrap and break-glass recovery only; day-to-day platform access is by platform account sign-in). `BRAND_LOCAL` / `BRAND_ORG` — display branding; also consulted once by the multi-local migration when naming the default local for pre-existing data. `NODE_ENV=production` — enables secure cookies (requires HTTPS).

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
