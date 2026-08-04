/**
 * sourcehash.js — a reproducible fingerprint of the deployed application code.
 *
 * WHY: this system asks members to trust a server they cannot personally
 * inspect at the moment they vote. One of the safeguards that substitutes for
 * that is transparency of the running code. This module produces a stable
 * SHA-256 "source fingerprint" that an observer can reproduce from an
 * independent checkout of the published source and compare to the value shown
 * on the observer dashboard — confirming the deployed server is the code that
 * was reviewed. It also surfaces the deployed git commit (Render sets
 * RENDER_GIT_COMMIT), which is the value most easily checked against GitHub.
 *
 * ALGORITHM (documented so anyone can reproduce it):
 *   1. Collect these files: server.js, package.json, public/style.css,
 *      public/logo.svg, and every .js/.ejs/.css/.svg/.json file under src/
 *      and views/ (recursively).
 *   2. Sort by repository-relative POSIX path.
 *   3. For each file compute sha256(file bytes) as lowercase hex.
 *   4. Feed "<relpath>\0<filehash>\n" for each file, in order, into one final
 *      sha256. Its hex digest is the source fingerprint.
 *
 * It deliberately EXCLUDES the data directory, environment/secrets, and
 * node_modules — none of those define the voting behaviour, and some are
 * sensitive.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const INCLUDE_FILES = ['server.js', 'package.json', 'public/style.css', 'public/logo.svg'];
const INCLUDE_DIRS = ['src', 'views'];
const EXT = new Set(['.js', '.ejs', '.css', '.svg', '.json']);

function walk(dir, acc) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return acc; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walk(full, acc);
    else if (EXT.has(path.extname(e.name))) acc.push(full);
  }
  return acc;
}

function computeSourceHash() {
  const files = [];
  for (const f of INCLUDE_FILES) files.push(path.join(ROOT, f));
  for (const d of INCLUDE_DIRS) walk(path.join(ROOT, d), files);

  /* Deduplicate and order deterministically by repo-relative POSIX path. */
  const byRel = new Map();
  for (const f of files) {
    const rel = path.relative(ROOT, f).split(path.sep).join('/');
    if (!byRel.has(rel)) byRel.set(rel, f);
  }
  const rels = [...byRel.keys()].sort();

  const outer = crypto.createHash('sha256');
  let counted = 0;
  for (const rel of rels) {
    let buf;
    try { buf = fs.readFileSync(byRel.get(rel)); } catch { continue; }
    const fileHash = crypto.createHash('sha256').update(buf).digest('hex');
    outer.update(rel + '\0' + fileHash + '\n');
    counted += 1;
  }
  return { hash: outer.digest('hex'), files: counted };
}

/* Computed once at startup: the source cannot change under a running process. */
const RESULT = computeSourceHash();
const SOURCE_HASH = RESULT.hash;
const SOURCE_FILE_COUNT = RESULT.files;
const GIT_COMMIT =
  process.env.RENDER_GIT_COMMIT || process.env.GIT_COMMIT || process.env.SOURCE_COMMIT || null;
const REPO_URL = process.env.SOURCE_REPO_URL || null; // optional, to link the commit

module.exports = { SOURCE_HASH, SOURCE_FILE_COUNT, GIT_COMMIT, REPO_URL, computeSourceHash };
