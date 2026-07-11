# Union Ballot

A self-hosted, secret-ballot electronic voting system for IAFF locals, built to the U.S. Department of Labor OLMS Compliance Tip *Electing Union Officers Using Remote Electronic Voting Systems* (updated December 2024) and the IAFF Legal Department's *Best Practices and Model Rules* guidance. It handles officer elections, delegate elections, dues and assessment votes, contract ratifications, bylaw amendments, and budget approvals, at local sizes from a dozen members to several thousand.

## The central guarantee

No one — including the administrator, the election committee, or anyone with a copy of the database — can learn how any member voted. This is architectural, not procedural:

Ballots are encrypted in the browser request the instant they are cast, using a sealed-box construction to the election's public key. The stored ballot row contains exactly three things: a random UUID, the election number, and ciphertext. No member ID, no credential reference, no timestamp, and (because the table is `WITHOUT ROWID` keyed on a random UUID) not even a physical insertion order. The matching decryption key is never stored anywhere: at election creation it is split with Shamir's Secret Sharing into N shares shown exactly once and handed to keyholders you choose — typically one representative per candidate slate plus a neutral. Reading even a single ballot requires K of those N people to act together at the tally ceremony, and even then the decrypted ballots carry no identity. What the committee *can* see is who has voted (the turnout list observers are traditionally entitled to compile) — never how.

Credentials are random 80-bit codes stored only as salted hashes; the plaintext exists only in the delivery email or the one-time export screen. Credential redemption is recorded by date only, so it cannot be correlated with any ballot. Every administrative action lands in a hash-chained, tamper-evident audit log that observers can verify live.

## Quick start

Requires Node.js 18+.

```bash
npm install
npm run smoke     # optional: runs a full election end-to-end and verifies every guarantee
npm start         # http://localhost:3000
```

Visit `/setup` on first run to create the election-committee admin account. Add observer accounts (one per candidate) under Accounts. The voter-facing page is the root URL — voters never log in; they only enter their credential.

## Configuration (environment variables)

`PORT` — listen port (default 3000). `BASE_URL` — the public https URL, used in credential emails. `DATA_DIR` — where the SQLite database lives (default `./data`). `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `MAIL_FROM` — email delivery of credentials; if unset, credentials are shown once for mail-merge delivery instead. `REISSUE_KEY` — optional 64-hex-char key for the encrypted member↔credential map used only to void-and-reissue lost credentials (auto-generated if unset). `NODE_ENV=production` — enables secure cookies (requires HTTPS).

## Production deployment

Run behind HTTPS — this is non-negotiable for a real election. The simplest defensible setup is a small VPS with Caddy or nginx terminating TLS in front of `node server.js` under systemd, with `NODE_ENV=production` and `BASE_URL` set. Back up the `data` directory; it contains only hashed credentials and encrypted ballots, but it *is* the election record you must retain for one year. The key shares are the one thing that cannot be recovered: if fewer than the threshold number survive, the ballots can never be opened and the election must be rerun, so treat share custody as seriously as a physical ballot box key.

## Running an election

The workflow the app enforces: create the vote (for officer, delegate, and dues votes it requires you to record IAFF Legal Department approval of the platform and procedures, per the IAFF Best Practices and Model Rules) → the key ceremony displays the decryption shares exactly once for distribution to keyholders → issue credentials (eligibility is frozen from the roster at that moment; members without email or who opt for paper are listed for the alternative method) → open voting → close voting → tally ceremony with K keyholders and observers present → publish results and export the records archive.

Run a **test election** first. Mark it as a test at creation, let candidate observers cast practice ballots and watch the tally — OLMS explicitly views observable test runs favorably, and it builds member confidence.

See `COMPLIANCE.md` for the requirement-by-requirement mapping to the LMRDA/OLMS guidance and the IAFF model rules, plus the procedural checklist of obligations that software cannot satisfy for you.

## What this system deliberately does not do

It never shows a voter their recorded choices after casting (an echo screen becomes a coercion tool), it never logs ballot events with identity, it never stores credential plaintext, and it never stores the election private key. There is no "admin override" to open ballots — that absence is the feature.
