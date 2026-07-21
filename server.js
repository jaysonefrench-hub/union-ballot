/**
 * server.js — Union Ballot: secret-ballot electronic voting for IAFF locals.
 * Built to the DOL/OLMS Compliance Tip on remote electronic voting (Dec 2024)
 * and the IAFF sample local Constitution & By-Laws election provisions.
 */
'use strict';

const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const { db, audit } = require('./src/db');
const { randomHex } = require('./src/crypto');

const app = express();
app.set('trust proxy', 1); // behind a hosting provider's HTTPS proxy (Render, etc.)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* Do not cache anything: ballots must never linger in shared caches. */
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
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
let sessionSecret = getSetting('session_secret');
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
 * Branding — configurable via environment variables so the district/local name
 * and logo can change without editing code. Drop your OFFICIAL logo artwork in
 * public/ (e.g. public/logo.png) and point BRAND_LOGO at it; the shipped
 * public/logo.svg is only a neutral placeholder to be replaced.
 */
const BRAND = {
  org: process.env.BRAND_ORG || 'IAFF District 12',
  local: process.env.BRAND_LOCAL || '',          // e.g. "Local 1234" (optional)
  system: process.env.BRAND_SYSTEM || 'Secret Ballot',
  logo: process.env.BRAND_LOGO || '/logo.png',
  footer: process.env.BRAND_FOOTER || 'Conducted under the IAFF Constitution & By-Laws and applicable law.',
};

/* Make user + flash + branding available to all views */
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.flash = req.session.flash || null;
  res.locals.brand = BRAND;
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

/* ----- first-run setup ----- */
function adminExists() {
  return !!db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get();
}

app.get('/setup', (req, res) => {
  if (adminExists()) return res.redirect('/login');
  res.render('setup', { title: 'First-run setup' });
});

app.post('/setup', (req, res) => {
  if (adminExists()) return res.redirect('/login');
  const { username, password, display_name } = req.body;
  if (!username || !password || password.length < 10) {
    flash(req, 'error', 'Choose a username and a password of at least 10 characters.');
    return res.redirect('/setup');
  }
  const hash = bcrypt.hashSync(password, 12);
  db.prepare('INSERT INTO users (username, password_hash, role, display_name) VALUES (?,?,?,?)')
    .run(username.trim(), hash, 'admin', (display_name || username).trim());
  audit('system', 'setup.admin_created', `Election-committee admin account "${username.trim()}" created`);
  flash(req, 'ok', 'Administrator account created. Sign in.');
  res.redirect('/login');
});

/* ----- login/logout ----- */
app.get('/login', (req, res) => {
  if (!adminExists()) return res.redirect('/setup');
  res.render('login', { title: 'Sign in' });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE username=?').get((username || '').trim());
  if (!u || !bcrypt.compareSync(password || '', u.password_hash)) {
    audit('system', 'auth.failed_login', `Failed sign-in attempt for username "${(username || '').trim()}"`);
    flash(req, 'error', 'Sign-in failed. Check the username and password.');
    return res.redirect('/login');
  }
  req.session.user = { id: u.id, username: u.username, role: u.role, name: u.display_name };
  audit(u.username, 'auth.login', `${u.role} signed in`);
  res.redirect(u.role === 'admin' ? '/admin' : '/observe');
});

app.post('/logout', (req, res) => {
  const who = req.session.user ? req.session.user.username : 'unknown';
  req.session.destroy(() => {
    audit(who, 'auth.logout', null);
    res.redirect('/');
  });
});

/* ----- routes ----- */
app.use('/', require('./src/routes/voter')({ flash }));
app.use('/admin', requireRole('admin'), require('./src/routes/admin')({ flash }));
app.use('/observe', requireRole('observer', 'admin'), require('./src/routes/observer')({ flash }));

app.use((req, res) => res.status(404).render('error', { title: 'Not found', message: 'That page does not exist.' }));
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error(err);
  audit('system', 'error', String(err.message || err).slice(0, 300));
  res.status(500).render('error', { title: 'Something went wrong', message: err.publicMessage || 'The action could not be completed. The error was recorded in the audit log.' });
});

const PORT = Number(process.env.PORT || 3000);
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Union Ballot running on http://localhost:${PORT}`);
    if (!adminExists()) console.log(`First run: visit http://localhost:${PORT}/setup to create the election-committee admin account.`);
  });
}
module.exports = app;
