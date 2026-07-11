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
  return {
    publicKey: Buffer.from(kp.publicKey).toString('base64'),
    // Shares are prefixed so keyholders can identify them later.
    shares: shareBufs.map((s, i) => `SHARE-${i + 1}-${s.toString('hex')}`),
  };
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
  if (secret.length !== nacl.box.secretKeyLength) {
    throw new Error('Combined shares did not produce a valid key. Check that each share is complete and from this election.');
  }
  return new Uint8Array(secret);
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
  const message = Buffer.from(JSON.stringify(ballotObj), 'utf8');
  const eph = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const pub = new Uint8Array(Buffer.from(electionPublicKeyB64, 'base64'));
  const boxed = nacl.box(new Uint8Array(message), nonce, pub, eph.secretKey);
  return JSON.stringify({
    e: Buffer.from(eph.publicKey).toString('base64'),
    n: Buffer.from(nonce).toString('base64'),
    c: Buffer.from(boxed).toString('base64'),
  });
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
  return JSON.parse(Buffer.from(opened).toString('utf8'));
}

/* ------------------------------------------------------------------ */
/* Voting credentials                                                  */
/* ------------------------------------------------------------------ */

const CRED_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I

/** Generate a human-typeable, high-entropy credential: XXXX-XXXX-XXXX-XXXX (~80 bits). */
function generateCredential() {
  const bytes = crypto.randomBytes(16);
  let out = '';
  for (let i = 0; i < 16; i++) {
    out += CRED_ALPHABET[bytes[i] % CRED_ALPHABET.length];
    if (i % 4 === 3 && i !== 15) out += '-';
  }
  return out;
}

function normalizeCredential(input) {
  return String(input || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

/**
 * Salted hash of a credential for at-rest storage. SHA-256 is appropriate
 * here (rather than a slow KDF) because credentials are uniformly random
 * ~80-bit secrets — offline brute force of the space is infeasible — and
 * verification must be O(1)-fast at 2,000-member scale.
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
  const key = Buffer.from(keyHex, 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv.toString('hex'), tag.toString('hex'), ct.toString('hex')].join(':');
}

function aesDecrypt(payload, keyHex) {
  const key = Buffer.from(keyHex, 'hex');
  const [ivH, tagH, ctH] = payload.split(':');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivH, 'hex'));
  decipher.setAuthTag(Buffer.from(tagH, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(ctH, 'hex')), decipher.final()]).toString('utf8');
}

/* ------------------------------------------------------------------ */
/* Hash-chained audit log support                                      */
/* ------------------------------------------------------------------ */

function chainHash(prevHash, entryJson) {
  return crypto.createHash('sha256').update(prevHash + '|' + entryJson).digest('hex');
}

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
  randomId,
  randomHex,
};
