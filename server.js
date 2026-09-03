/**
 * server.js — Union Ballot: secret-ballot electronic voting for union locals.
 * Built to the DOL/OLMS Compliance Tip on remote electronic voting (Dec 2024)
 * and to published union model rules for officer elections.
 */
'use strict';

const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const { db, audit } = require('./src/db');
const { randomHex } = require('./src/crypto');
const { resolveLocal, platformAdminExists } = require('./src/tenant');
const { SOURCE_HASH, SOURCE_FILE_COUNT, GIT_COMMIT, REPO_URL } = require('./src/sourcehash');

/* ----- crash handlers: log the error, never the request ----- */
process.on('unhandledRejection', (reason) => {
  const e = reason instanceof Error ? reason : new Error(String(reason));
  console.error('[unhandledRejection]', e.message);
  if (e.stack) console.error(e.stack);
});

process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err.message);
  console.error(err.stack);
  process.exit(1);
});

const app = express();
app.set('trust proxy', 1); // behind a hosting provider's HTTPS proxy (Render, etc.)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* Do not cache anything: ballots must never linger in shared caches.
 * no-referrer keeps a credential out of any Referer header if one ever
 * appears in a URL. */
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('X-Content-Type-Options', 'nosniff');
  next();
});

/* Session secret persists across restarts via settings table. */
function getSetting(key) {
  const r = db.prepare('SELECT value FROM settings WHERE key=?').get(key);
  return r ? r.value : null;
}
function setSetting(key, value) {
  db.prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key, value);
}
/* SESSION_SECRET may be supplied from the environment so it does not have to
 * live inside the database file that gets backed up and retained. */
let sessionSecret = process.env.SESSION_SECRET || getSetting('session_secret');
if (!sessionSecret) { sessionSecret = randomHex(32); setSetting('session_secret', sessionSecret); }

app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production', // requires HTTPS in production
    maxAge: 1000 * 60 * 60 * 4,
  },
}));

/*
 * Branding — every value is configurable by environment variable so a local
 * can put its own name and seal on the ballot without editing code.
 *
 * AFFILIATION NOTE: the defaults below are deliberately vendor-neutral. This
 * software is not affiliated with, endorsed by, or a product of any labor
 * organization. Do not reintroduce any union's name, seal, insignia, or
 * trademark as a shipped default — those marks belong to their owners, and a
 * local that adopts this system sets its own identity through BRAND_ORG and
 * BRAND_LOCAL at deployment time.
 *
 * Describing the standards this system is built to (DOL/OLMS guidance,
 * published model rules) is a statement of conformance, not affiliation, and
 * is accurate to make.
 */
const BRAND = {
  org: process.env.BRAND_ORG || 'Union Ballot',
  local: process.env.BRAND_LOCAL || '',          // e.g. "Local 1234" (optional)
  system: process.env.BRAND_SYSTEM || 'Secret ballot',
  tagline: process.env.BRAND_TAGLINE || 'Secret-ballot elections for union locals',
  logo: process.env.BRAND_LOGO || '/logo.svg',
  footer: process.env.BRAND_FOOTER || 'Conducted under the local\'s constitution and by-laws and applicable law.',

  /* Demo mode: set DEMO=1 on the public demonstration instance. Templates use
   * this to show a standing notice on every page. Never set it on an instance
   * that will hold a binding election, and never load a real roster into an
   * instance where it is set. */
  demo: process.env.DEMO === '1',
  demoNotice: process.env.DEMO_NOTICE
    || 'Demonstration site. Practice ballots only — nothing here is a real election, and no result is binding.',
};

/* Make user + flash + branding available to all views */
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.flash = req.session.flash || null;
  res.locals.brand = BRAND;
  /* The signed-in committee/observer's local, shown in the header of every
   * page so it is always unambiguous WHICH local this session manages (the
   * same person may hold accounts at more than one local). resolveLocal
   * re-resolves and ENFORCES it on /admin and /observe requests; this lookup
   * is display-only. */
  res.locals.currentLocal = null;
  if (req.session.user) {
    const row = db.prepare('SELECT l.* FROM locals l JOIN users u ON u.local_id=l.id WHERE u.id=?').get(req.session.user.id);
    res.locals.currentLocal = row || null;
  }
  /* Platform administrator session (separate role, separate table). */
  res.locals.platformAdmin = (req.session && req.session.platform_admin) || null;
  /* Set true only on pages that belong to a TEST election — never globally. */
  res.locals.electionIsTest = false;
  /* Deployed-code transparency: observers can compare this to an independent
     build of the published source, and the commit to the public repository. */
  res.locals.source = { hash: SOURCE_HASH, fileCount: SOURCE_FILE_COUNT, commit: GIT_COMMIT, repoUrl: REPO_URL };
  delete req.session.flash;
  next();
});

function flash(req, type, text) { req.session.flash = { type, text }; }

/* ----- auth middleware ----- */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.session.user) return res.redirect('/login');
    if (!roles.includes(req.session.user.role)) {
      return res.status(403).render('error', { title: 'Not authorized', message: 'Your account does not have access to that page.' });
    }
    next();
  };
}

/* ----- first-run setup (legacy path) -----
 * Committee accounts are no longer self-claimed on first run: a local — and
 * its first committee-admin account — is provisioned by the platform
 * administrator (/platform). The old /setup URL survives only as a signpost
 * so bookmarks and the previous README instructions land somewhere sensible. */
function anyCommitteeAccountExists() {
  return !!db.prepare('SELECT id FROM users LIMIT 1').get();
}

app.all('/setup', (req, res) => {
  if (!platformAdminExists() && !anyCommitteeAccountExists()) return res.redirect('/platform/setup');
  return res.redirect('/login');
});

/* ----- login/logout ----- */
app.get('/login', (req, res) => {
  /* Brand-new instance: nothing to sign in to yet — start the platform
   * bootstrap instead (it creates the platform admin, who creates locals). */
  if (!platformAdminExists() && !anyCommitteeAccountExists()) return res.redirect('/platform/setup');
  res.render('login', { title: 'Sign in' });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE username=?').get((username || '').trim());
  if (!u || !bcrypt.compareSync(password || '', u.password_hash)) {
    /* The submitted username is deliberately NOT recorded: a voter who pastes a
     * ballot credential into this box would otherwise write it into the
     * permanent, observer-visible audit log. The attempt itself is the
     * loggable event. Attributed to the account's local when the username
     * exists (its observers are entitled to see failed attempts on their own
     * accounts); otherwise to the platform chain. */
    audit(u ? u.local_id : null, 'system', 'auth.failed_login', 'Failed sign-in attempt (submitted username not recorded)');
    flash(req, 'error', 'Sign-in failed. Check the username and password.');
    return res.redirect('/login');
  }
  /* local_id rides in the session for logout attribution; every scoped page
   * re-resolves it from the database via resolveLocal. */
  req.session.user = { id: u.id, username: u.username, role: u.role, name: u.display_name, local_id: u.local_id };
  audit(u.local_id, u.username, 'auth.login', `${u.role} signed in`);
  res.redirect(u.role === 'admin' ? '/admin' : '/observe');
});

app.post('/logout', (req, res) => {
  const who = req.session.user ? req.session.user.username : 'unknown';
  const localId = req.session.user ? req.session.user.local_id : null;
  req.session.destroy(() => {
    audit(localId ?? null, who, 'auth.logout', null);
    res.redirect('/');
  });
});

/* ----- routes ----- */
app.use('/', require('./src/routes/voter')({ flash }));
/* Password recovery (/forgot-password, /reset-password): public by nature —
 * the whole point is that the person is locked out — protected by hash-only
 * single-use tokens, not sessions. */
app.use('/', require('./src/routes/recovery')({ flash }));
/* Committee/observer routes: role check first, then resolveLocal pins the
 * request to the signed-in account's ONE local — every query inside these
 * routers is scoped to req.localId. The whole-database backup deliberately
 * no longer lives under /admin: it spans every local, so it belongs to the
 * platform administrator (src/routes/platform.js). */
app.use('/admin', requireRole('admin'), resolveLocal, require('./src/routes/admin')({ flash }));
app.use('/observe', requireRole('observer', 'admin'), resolveLocal, require('./src/routes/observer')({ flash }));
/* Platform administration (per-local aggregate stats, local creation,
 * archives, recovery): authenticated by its own platform_users accounts —
 * deliberately NOT by requireRole. A committee or observer session grants
 * nothing here, and a platform admin holds no committee account. */
app.use('/platform', require('./src/routes/platform')({ flash }));

app.use((req, res) => res.status(404).render('error', { title: 'Not found', message: 'That page does not exist.' }));

/* ----- error handler -----
 * Ballot secrecy rule: an error raised on a voter-facing request must not put
 * any submitted value into the console, the audit log, or the response. The
 * credential and the plaintext choices arrive in the same POST body, so a
 * single careless log line would create exactly the voter-to-vote link the
 * whole system is built to prevent.
 */
function stackFramesOnly(stack) {
  return String(stack || '')
    .split('\n')
    .filter((line) => /^\s+at\s/.test(line))
    .slice(0, 12)
    .join('\n');
}

app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  /* express.urlencoded attaches the raw request body to err.body when parsing
   * fails. Drop it immediately so nothing downstream can reach it. */
  if (err && err.body) delete err.body;

  /* Signed-in admin/observer requests get full detail. Every other request —
   * which includes every voter-facing page, and therefore ballot casting —
   * gets none. This fails safe: a new voter route needs no configuration here. */
  const signedIn = !!(req.session && req.session.user);
  const routePath = String(req.originalUrl || '').split('?')[0]; // never log a query string
  const safeMsg = String((err && err.message) || 'unknown error').slice(0, 200);

  if (signedIn) {
    console.error('[error]', req.method, routePath, '-', safeMsg);
    if (err && err.stack) console.error(err.stack);
  } else {
    /* Message withheld; stack frames (file and line only) are kept so a
     * failure is still diagnosable without exposing any submitted value. */
    console.error('[error]', req.method, routePath, '- detail withheld (voter-facing route)');
    if (err && err.stack) console.error(stackFramesOnly(err.stack));
  }

  try {
    /* Attribute the entry to the signed-in account's local chain when there
     * is one; anonymous/voter-facing and platform errors go to the platform
     * chain. Never a local id derived from any submitted value. */
    const errLocalId = req.localId ?? (req.session && req.session.user ? req.session.user.local_id : null) ?? null;
    audit(errLocalId, 'system', 'error', signedIn
      ? `${req.method} ${routePath} — ${safeMsg}`
      : `${req.method} ${routePath} — detail withheld (voter-facing route)`);
  } catch (_) {
    /* An audit-write failure must never mask the original error. */
  }

  if (res.headersSent) return;
  /* Tenant-scoped fetches raise status 404: a guessed id from another local
   * renders exactly like an id that never existed. */
  const status = (err && err.status) === 404 ? 404 : 500;
  res.status(status).render('error', {
    title: status === 404 ? 'Not found' : 'Something went wrong',
    message: (err && err.publicMessage) || 'The action could not be completed. The error was recorded in the audit log.',
  });
});

const PORT = Number(process.env.PORT || 3000);
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Union Ballot running on http://localhost:${PORT}`);
    console.log(`Source fingerprint: ${SOURCE_HASH} (${SOURCE_FILE_COUNT} files)${GIT_COMMIT ? ' | commit ' + GIT_COMMIT.slice(0, 12) : ''}`);
    if (BRAND.demo) console.log('DEMO MODE is on. Do not load a real roster into this instance.');
    if (!platformAdminExists()) console.log(`First run: visit http://localhost:${PORT}/platform/setup to create the platform administrator, then create your first local from /platform.`);
  });
}
module.exports = app;
