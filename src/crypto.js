/**
 * crypto.js — Cryptographic core of the ballot secrecy architecture.
 *
 * Design goals (per DOL/OLMS Compliance Tip, "Electing Union Officers Using
 * Remote Electronic Voting Systems", updated Dec 2024):
 *
 *  1. NO PERSISTENT LINK between a voter and their ballot. Ballots are stored
 *     with no member ID, no credential ID, no timestamp, and no sequential
 *     row ID. They are encrypted the moment they are cast.
 *
 *  2. THRESHOLD DECRYPTION. The election private key is never stored by the
 *     system. At election creation it is split with Shamir's Secret Sharing
 *     into N shares held by different people (competing candidates' reps +
 *     a neutral). Decrypting the ballots for the official tally requires K
 *     of N shares entered together — no administrator can open ballots alone.
 *
 *  3. HIGH-ENTROPY RANDOM CREDENTIALS. Voting credentials are generated from
 *     a CSPRNG and stored only as salted hashes.
 *
 *  4. TAMPER-EVIDENT AUDIT LOG. Every logged event is chained to the previous
 *     entry's hash, so any alteration of history breaks the chain.
 */
'use strict';

const crypto = require('crypto');
const nacl = require('tweetnacl');
const sss = require('shamirs-secret-sharing');

/* ------------------------------------------------------------------ */
/* Memory hygiene helper                                               */
/* ------------------------------------------------------------------ */

/**
 * Overwrite a Buffer or typed array with zeros.
 *
 * Honest scope: this narrows the window in which secret material sits in
 * process memory. It does not eliminate it — the JavaScript engine may hold
 * copies of strings and objects that cannot be reached or overwritten from
 * application code. It is defense in depth, not a guarantee, and it is not a
 * substitute for the architectural protections (threshold decryption, no
 * voter-to-ballot join path) that the secrecy claim actually rests on.
 */
function zeroize(buf) {
  if (buf && typeof buf.fill === 'function') buf.fill(0);
}

/**
 * Validate a 256-bit hex key before use. Guards against the most likely
 * real-world deployment error: a REISSUE_KEY environment variable that was
 * truncated, padded with whitespace, or pasted with the wrong length. Without
 * this check, the failure surfaces as an opaque "Invalid key length" from
 * Node's cipher layer, potentially in the middle of an election.
 *
 * The error reports the LENGTH only — never any portion of the key itself.
 */
function assertKeyHex(keyHex, label) {
  if (typeof keyHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(keyHex.trim())) {
    const got = typeof keyHex === 'string' ? `${keyHex.trim().length} characters` : typeof keyHex;
    throw Object.assign(
      new Error(`${label} must be exactly 64 hexadecimal characters (a 256-bit key); got ${got}.`),
      { publicMessage: 'Server is misconfigured: the reissue key is missing or the wrong length. No ballot was affected. Contact the administrator.' }
    );
  }
  return Buffer.from(keyHex.trim(), 'hex');
}

/* ------------------------------------------------------------------ */
/* Election keypair + Shamir shares                                    */
/* ------------------------------------------------------------------ */

/**
 * Generate an X25519 keypair for an election and split the private key
 * into `shares` Shamir shares with the given `threshold`.
 * The private key is returned ONLY so shares can be shown once; it is the
 * caller's responsibility never to persist it.
 */
function generateElectionKeys(shares, threshold) {
  const kp = nacl.box.keyPair();
  const secretBuf = Buffer.from(kp.secretKey);
  const shareBufs = sss.split(secretBuf, { shares, threshold });
  const result = {
    publicKey: Buffer.from(kp.publicKey).toString('base64'),
    // Shares are prefixed so keyholders can identify them later.
    shares: shareBufs.map((s, i) => `SHARE-${i + 1}-${s.toString('hex')}`),
  };
  /* The private key now exists only inside the shares. Wipe our copies. */
  zeroize(secretBuf);
  zeroize(kp.secretKey);
  return result;
}

/** Parse a share string back to its raw buffer. Accepts pasted whitespace. */
function parseShare(text) {
  const cleaned = String(text || '').trim();
  const m = cleaned.match(/^SHARE-\d+-([0-9a-fA-F]+)$/);
  if (!m) throw new Error('Share format not recognized. Expected SHARE-<n>-<hex>.');
  return Buffer.from(m[1], 'hex');
}

/** Reconstruct the election private key from K share strings. */
function combineShares(shareTexts) {
  const bufs = shareTexts.map(parseShare);
  const secret = sss.combine(bufs);
  bufs.forEach(zeroize);
  if (secret.length !== nacl.box.secretKeyLength) {
    zeroize(secret);
    throw new Error('Combined shares did not produce a valid key. Check that each share is complete and from this election.');
  }
  const key = new Uint8Array(secret);
  zeroize(secret);
  /* CALLER CONTRACT: pass this key to zeroize() as soon as the tally is
   * finished. It must never be written to a file, a log, or the database. */
  return key;
}

/* ------------------------------------------------------------------ */
/* Sealed-box ballot encryption                                        */
/* ------------------------------------------------------------------ */

/**
 * Encrypt a ballot object to the election public key using an ephemeral
 * keypair (sealed-box construction). The ephemeral secret key is discarded
 * immediately, so only holders of K key shares can ever decrypt.
 */
function encryptBallot(ballotObj, electionPublicKeyB64) {
  const message = new Uint8Array(Buffer.from(JSON.stringify(ballotObj), 'utf8'));
  const eph = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const pub = new Uint8Array(Buffer.from(electionPublicKeyB64, 'base64'));
  const boxed = nacl.box(message, nonce, pub, eph.secretKey);
  const sealed = JSON.stringify({
    e: Buffer.from(eph.publicKey).toString('base64'),
    n: Buffer.from(nonce).toString('base64'),
    c: Buffer.from(boxed).toString('base64'),
  });
  /* Wipe the plaintext ballot and the ephemeral secret. Once the ephemeral
   * secret is gone, not even this process can reopen what it just sealed. */
  zeroize(message);
  zeroize(eph.secretKey);
  return sealed;
}

/** Decrypt one stored ballot with the reconstructed private key. */
function decryptBallot(stored, privateKey) {
  const { e, n, c } = JSON.parse(stored);
  const opened = nacl.box.open(
    new Uint8Array(Buffer.from(c, 'base64')),
    new Uint8Array(Buffer.from(n, 'base64')),
    new Uint8Array(Buffer.from(e, 'base64')),
    privateKey
  );
  if (!opened) throw new Error('A ballot failed to decrypt — possible tampering or wrong key shares.');
  const obj = JSON.parse(Buffer.from(opened).toString('utf8'));
  zeroize(opened);
  return obj;
}

/* ------------------------------------------------------------------ */
/* Voting credentials                                                  */
/* ------------------------------------------------------------------ */

/*
 * Exactly 32 characters, and 32 divides 256 evenly — so the `% length`
 * reduction below is perfectly uniform with no modulo bias. 16 characters at
 * 5 bits each = exactly 80 bits of entropy. Do not add or remove characters
 * from this alphabet without re-checking that property.
 */
const CRED_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I

/** Generate a human-typeable, high-entropy credential: XXXX-XXXX-XXXX-XXXX (~80 bits). */
function generateCredential() {
  const bytes = crypto.randomBytes(16);
  let out = '';
  for (let i = 0; i < 16; i++) {
    out += CRED_ALPHABET[bytes[i] % CRED_ALPHABET.length];
    if (i % 4 === 3 && i !== 15) out += '-';
  }
  zeroize(bytes);
  return out;
}

function normalizeCredential(input) {
  return String(input || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

/**
 * Salted hash of a credential for at-rest storage. SHA-256 is appropriate
 * here (rather than a slow KDF like scrypt or bcrypt) because credentials are
 * uniformly random 80-bit secrets — offline brute force of that space is
 * infeasible regardless of hash speed.
 *
 * NOTE ON LOOKUP COST: because each credential carries its own random salt,
 * a credential cannot be looked up by index. Verification scans the live
 * credentials for the open election and hashes each one, i.e. it is O(n) in
 * roster size, not O(1). This is a deliberate trade — the per-credential salt
 * means two members issued the same code would not produce the same stored
 * hash — but it is the reason rate limiting on credential submission matters
 * more here than in a typical login form.
 */
function hashCredential(credential, salt) {
  const norm = normalizeCredential(credential);
  return crypto.createHash('sha256').update(salt + '|' + norm).digest('hex');
}

/* ------------------------------------------------------------------ */
/* Symmetric encryption for the credential->member reissue map         */
/* ------------------------------------------------------------------ */
/*
 * To allow reissuing a credential to a member who lost theirs (an OLMS
 * observer-rights expectation: "subsequent distributions to members who did
 * not receive or who lost credentials"), the system keeps an ENCRYPTED
 * member<->credential-hash mapping. This mapping never touches ballots:
 * ballots contain no credential reference, so even with this map decrypted
 * no one can learn how anyone voted — only that they were issued a
 * credential and whether it was redeemed (turnout), which observers are
 * traditionally entitled to see.
 */

function aesEncrypt(plaintext, keyHex) {
  const key = assertKeyHex(keyHex, 'REISSUE_KEY');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const out = [iv.toString('hex'), tag.toString('hex'), ct.toString('hex')].join(':');
  zeroize(key);
  return out;
}

function aesDecrypt(payload, keyHex) {
  const key = assertKeyHex(keyHex, 'REISSUE_KEY');
  const [ivH, tagH, ctH] = String(payload || '').split(':');
  if (!ivH || !tagH || !ctH) {
    zeroize(key);
    throw Object.assign(
      new Error('Reissue-map entry is malformed or has been purged.'),
      { publicMessage: 'That credential record is no longer available. Contact the election committee.' }
    );
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivH, 'hex'));
  decipher.setAuthTag(Buffer.from(tagH, 'hex'));
  const out = Buffer.concat([decipher.update(Buffer.from(ctH, 'hex')), decipher.final()]).toString('utf8');
  zeroize(key);
  return out;
}

/* ------------------------------------------------------------------ */
/* Hash-chained audit log support                                      */
/* ------------------------------------------------------------------ */

function chainHash(prevHash, entryJson) {
  return crypto.createHash('sha256').update(prevHash + '|' + entryJson).digest('hex');
}

/* ------------------------------------------------------------------ */
/* Cryptographically-random shuffle (used at tally)                    */
/* ------------------------------------------------------------------ */

/**
 * Return a new array that is a uniformly random permutation of `arr`,
 * using a CSPRNG (Fisher–Yates with crypto.randomInt). Used to shuffle
 * ballots before decryption so the tally reveals nothing about order,
 * without relying on the non-cryptographic Math.random().
 */
function secureShuffle(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/**
 * Random ballot identifier. crypto.randomUUID() produces a version 4 UUID —
 * 122 random bits, no timestamp and no counter. This is load-bearing: the
 * ballots table is WITHOUT ROWID and keyed on this value, so if it were ever
 * changed to a time-ordered identifier (UUID v1 or v7), physical storage
 * order would silently become casting order and the secrecy guarantee would
 * be defeated with no visible symptom. Do not change this.
 */
function randomId() {
  return crypto.randomUUID();
}

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString('hex');
}

module.exports = {
  generateElectionKeys,
  combineShares,
  encryptBallot,
  decryptBallot,
  generateCredential,
  normalizeCredential,
  hashCredential,
  aesEncrypt,
  aesDecrypt,
  chainHash,
  secureShuffle,
  randomId,
  randomHex,
  zeroize,
};
