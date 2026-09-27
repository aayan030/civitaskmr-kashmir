const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { readJSON, writeJSON, withLock } = require('./store');

const isProd = process.env.NODE_ENV === 'production';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 14; // 14 days

// ---------------------------------------------------------------------------
// Sessions live server-side (id -> session object). The browser only ever
// holds a random, unguessable session id in an httpOnly cookie — never a
// username/password/role, and never anything an attacker could tamper with
// to escalate role, since the role is looked up server-side by session id.
// ---------------------------------------------------------------------------
let sessions = readJSON('sessions', {});

function persistSessions() {
  writeJSON('sessions', sessions);
}

function pruneExpired() {
  const now = Date.now();
  let changed = false;
  for (const [id, s] of Object.entries(sessions)) {
    if (s.expiresAt < now) { delete sessions[id]; changed = true; }
  }
  if (changed) persistSessions();
}
setInterval(pruneExpired, 1000 * 60 * 30);
pruneExpired();

function createSession(data) {
  const id = crypto.randomBytes(32).toString('hex');
  sessions[id] = { ...data, expiresAt: Date.now() + SESSION_TTL_MS };
  persistSessions();
  return { id };
}

function getSession(id) {
  if (!id) return null;
  const s = sessions[id];
  if (!s) return null;
  if (s.expiresAt < Date.now()) { delete sessions[id]; persistSessions(); return null; }
  return s;
}

function destroySession(id) {
  if (id && sessions[id]) { delete sessions[id]; persistSessions(); }
}

const COOKIE_BASE = { httpOnly: true, sameSite: 'lax', secure: isProd, path: '/' };

function setSessionCookie(res, id) {
  res.cookie('sid', id, { ...COOKIE_BASE, maxAge: SESSION_TTL_MS });
}

// csrf_token is a plain double-submit-cookie token: NOT httpOnly (the
// frontend's api() helper reads it via document.cookie and echoes it back
// as X-CSRF-Token), and NOT tied to any particular login session — its only
// job is proving the request came from same-site JS, which is exactly what
// login/signup/public-form endpoints need before any session exists.
function ensureCsrfCookie(req, res, next) {
  if (!req.cookies.csrf_token) {
    const token = crypto.randomBytes(24).toString('hex');
    res.cookie('csrf_token', token, { sameSite: 'lax', secure: isProd, path: '/', maxAge: SESSION_TTL_MS });
    req.cookies.csrf_token = token; // so csrfProtection sees it on this same request
  }
  next();
}

function clearSessionCookie(res) {
  res.clearCookie('sid', { ...COOKIE_BASE });
}

// Attach req.session (or null) from the sid cookie. Runs on every request.
function sessionMiddleware(req, res, next) {
  req.session = getSession(req.cookies.sid);
  next();
}

// Require any signed-in session, of a given kind ('control' or 'user').
function requireSession(kind) {
  return (req, res, next) => {
    if (!req.session || req.session.kind !== kind) {
      return res.status(401).json({ error: 'Not signed in.' });
    }
    next();
  };
}

// Require control-mode session with one of the given roles.
function requireControlRole(...roles) {
  return (req, res, next) => {
    if (!req.session || req.session.kind !== 'control') {
      return res.status(401).json({ error: 'Not signed in to Control Mode.' });
    }
    if (!roles.includes(req.session.role)) {
      return res.status(403).json({ error: 'Your access level cannot do this.' });
    }
    next();
  };
}

// Standard double-submit-cookie CSRF check for any state-changing request.
// Works for both anonymous requests (signup/login/public form submissions)
// and authenticated ones, since it never depends on a session existing.
function csrfProtection(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const cookieToken = req.cookies.csrf_token;
  const headerToken = req.get('X-CSRF-Token');
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: 'Invalid or missing CSRF token. Refresh the page and try again.' });
  }
  next();
}

// ---------------------------------------------------------------------------
// Basic brute-force protection for the login endpoints (per IP + name).
// ---------------------------------------------------------------------------
const attempts = new Map(); // key -> { count, lockUntil }
const MAX_ATTEMPTS = 8;
const LOCK_MS = 1000 * 60 * 15;

function checkRateLimit(key) {
  const a = attempts.get(key);
  if (a && a.lockUntil > Date.now()) {
    return { blocked: true, retryAfterMs: a.lockUntil - Date.now() };
  }
  return { blocked: false };
}
function recordFailure(key) {
  const a = attempts.get(key) || { count: 0, lockUntil: 0 };
  a.count += 1;
  if (a.count >= MAX_ATTEMPTS) { a.lockUntil = Date.now() + LOCK_MS; a.count = 0; }
  attempts.set(key, a);
}
function recordSuccess(key) {
  attempts.delete(key);
}

module.exports = {
  createSession, getSession, destroySession,
  setSessionCookie, clearSessionCookie, ensureCsrfCookie,
  sessionMiddleware, requireSession, requireControlRole, csrfProtection,
  checkRateLimit, recordFailure, recordSuccess,
  bcryptCompare: (plain, hash) => bcrypt.compare(plain, hash),
  bcryptHash: (plain) => bcrypt.hash(plain, 12),
};
