require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const { readJSON, writeJSON, withLock, initStore, flushStore } = require('./lib/store');
const {
  createSession, getSession, destroySession,
  setSessionCookie, clearSessionCookie, ensureCsrfCookie,
  sessionMiddleware, requireControlRole, csrfProtection,
  checkRateLimit, recordFailure, recordSuccess,
  bcryptCompare, bcryptHash,
} = require('./lib/auth');

const path = require('path');
const app = express();
app.set('trust proxy', 1); // needed for correct req.ip behind Render/Railway/etc.
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use(ensureCsrfCookie);
app.use(sessionMiddleware);

// Serve the frontend from the same origin as the API — this is what makes
// the frontend's relative fetch('/api/...') calls work with no CORS setup,
// and lets the httpOnly session cookie apply to the whole site.
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Staff control-mode identities. Names are read from env; codes are NEVER
// read from env as plaintext — only as bcrypt hashes. If a hash isn't
// configured, that role's login is disabled rather than falling back to any
// built-in/default code. None of this reaches the frontend bundle: it only
// ever exists in this server process, reading from environment variables.
// ---------------------------------------------------------------------------
function parseNames(csv) {
  return (csv || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
}
const ADMIN_NAMES = parseNames(process.env.ADMIN_NAMES);
const ADMIN_CODE_HASH = process.env.ADMIN_CODE_HASH || null;
const ADMIN_CODE = process.env.ADMIN_CODE || null;
const DEPUTY_NAME = (process.env.DEPUTY_NAME || '').trim().toLowerCase();
const DEPUTY_CODE_HASH = process.env.DEPUTY_CODE_HASH || null;
const DEPUTY_CODE = process.env.DEPUTY_CODE || null;

if (!ADMIN_CODE_HASH && !ADMIN_CODE) console.warn('[startup] No admin code configured — admin control-mode login is disabled.');
if (!DEPUTY_CODE_HASH && !DEPUTY_CODE) console.warn('[startup] No deputy code configured — deputy control-mode login is disabled.');

function appendLog(msg) {
  const log = readJSON('log', []);
  log.unshift({ t: new Date().toISOString(), msg });
  writeJSON('log', log.slice(0, 500)); // cap growth
}

function bumpContentMeta() {
  writeJSON('content-meta', { updatedAt: Date.now() });
}

// =============================================================================
// BACKUP (admin-only)
// =============================================================================
function collectBackup() {
  const collections = ['content','applications','submissions','messages','log','users','content-backup'];
  const data = {};
  for (const name of collections) data[name] = readJSON(name, name === 'log' ? [] : (name === 'content' ? {} : []));
  return {
    format: 'civitas-backup',
    version: 1,
    createdAt: new Date().toISOString(),
    data,
  };
}

app.get('/api/backup', requireControlRole('admin'), (req, res) => {
  const backup = collectBackup();
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="civitas-backup-${new Date().toISOString().slice(0,10)}.json"`);
  res.json(backup);
});

app.post('/api/backup/restore', csrfProtection, requireControlRole('admin'), async (req, res) => {
  const backup = req.body || {};
  if (backup.format !== 'civitas-backup' || !backup.data || typeof backup.data !== 'object') {
    return res.status(400).json({ error: 'Invalid CIVITAS backup file.' });
  }
  const collections = ['content','applications','submissions','messages','log','users','content-backup'];
  for (const name of collections) {
    if (Object.prototype.hasOwnProperty.call(backup.data, name)) {
      await withLock(name, async () => writeJSON(name, backup.data[name]));
    }
  }
  appendLog(`${req.session.name} restored a CIVITAS data backup`);
  res.json({ ok: true });
});

// =============================================================================
// CONTENT  (admin-editable; everyone can read; polled every 8s by the client)
// =============================================================================
app.get('/api/content', (req, res) => {
  res.json({ content: readJSON('content', {}) });
});

app.get('/api/content/meta', (req, res) => {
  res.json({ meta: readJSON('content-meta', { updatedAt: 0 }) });
});

app.put('/api/content', csrfProtection, requireControlRole('admin'), async (req, res) => {
  const { content, activityMessage } = req.body || {};
  if (typeof content !== 'object' || content === null) {
    return res.status(400).json({ error: 'Missing content payload.' });
  }
  await withLock('content', async () => {
    // Keep the previous content as a safety copy on the persistent disk.
    writeJSON('content-backup', readJSON('content', {}));
    writeJSON('content', content);
    bumpContentMeta();
  });
  appendLog(activityMessage ? String(activityMessage).slice(0, 300) : `${req.session.name} updated site content`);
  res.json({ ok: true });
});

app.post('/api/content/reset', csrfProtection, requireControlRole('admin'), async (req, res) => {
  await withLock('content', async () => {
    writeJSON('content', {});
    bumpContentMeta();
  });
  appendLog(`${req.session.name} reset all site content to placeholder defaults`);
  res.json({ ok: true });
});

// =============================================================================
// APPLICATIONS  (public submit; admin+deputy review; both may approve/reject)
// =============================================================================
app.post('/api/applications', csrfProtection, async (req, res) => {
  const b = req.body || {};
  if (!b.name || !String(b.name).trim()) return res.status(400).json({ error: 'Name is required.' });
  if (!b.email || !String(b.email).trim()) return res.status(400).json({ error: 'Email is required.' });
  if (!b.why || !String(b.why).trim()) return res.status(400).json({ error: 'Please tell us why you want to join.' });

  const clean = (v, max) => (v === undefined || v === null ? '' : String(v).slice(0, max));
  const appRecord = {
    id: 'app_' + crypto.randomBytes(8).toString('hex'),
    name: clean(b.name, 200), email: clean(b.email, 500), phone: clean(b.phone, 200),
    age: clean(b.age, 10), location: clean(b.location, 500), school: clean(b.school, 500),
    dept: clean(b.dept, 200), why: clean(b.why, 4000), interest: clean(b.interest, 4000),
    experience: clean(b.experience, 4000), commitment: clean(b.commitment, 100), heard: clean(b.heard, 500),
    status: 'New', date: new Date().toISOString(),
    appliedByUsername: (req.session && req.session.kind === 'user') ? req.session.username : null,
  };

  await withLock('applications', async () => {
    const apps = readJSON('applications', []);
    apps.unshift(appRecord);
    writeJSON('applications', apps);
  });
  appendLog(`New application from ${appRecord.name}`);
  res.json({ ok: true });
});

app.get('/api/applications', requireControlRole('admin', 'deputy'), (req, res) => {
  res.json({ applications: readJSON('applications', []) });
});

app.post('/api/applications/:id/approve', csrfProtection, requireControlRole('admin', 'deputy'), async (req, res) => {
  const { id } = req.params;
  const linkUsername = (req.body && req.body.linkUsername) ? String(req.body.linkUsername).trim() : '';
  let promotedUsername = null;

  await withLock('applications', async () => {
    const apps = readJSON('applications', []);
    const rec = apps.find(a => a.id === id);
    if (!rec) return;
    rec.status = 'Approved';
    const usernameToPromote = rec.appliedByUsername || linkUsername || null;
    if (usernameToPromote) {
      await withLock('users', async () => {
        const users = readJSON('users', []);
        const user = users.find(u => u.username.toLowerCase() === usernameToPromote.toLowerCase());
        if (user) {
          user.role = 'member';
          writeJSON('users', users);
          rec.appliedByUsername = user.username;
          promotedUsername = user.username;
        }
      });
    }
    writeJSON('applications', apps);
  });

  appendLog(`${req.session.name} approved application ${id}${promotedUsername ? ` (promoted ${promotedUsername} to Member)` : ''}`);
  res.json({ ok: true, promotedUsername });
});

app.post('/api/applications/:id/reject', csrfProtection, requireControlRole('admin', 'deputy'), async (req, res) => {
  const { id } = req.params;
  await withLock('applications', async () => {
    const apps = readJSON('applications', []);
    const rec = apps.find(a => a.id === id);
    if (rec) { rec.status = 'Rejected'; writeJSON('applications', apps); }
  });
  appendLog(`${req.session.name} rejected application ${id}`);
  res.json({ ok: true });
});

// =============================================================================
// JOURNAL / RESEARCH SUBMISSIONS  (public submit; admin+deputy review)
// =============================================================================
app.post('/api/submissions', csrfProtection, async (req, res) => {
  const b = req.body || {};
  if (!b.name || !String(b.name).trim()) return res.status(400).json({ error: 'Name is required.' });
  if (!b.email || !String(b.email).trim()) return res.status(400).json({ error: 'Email is required.' });
  if (!b.title || !String(b.title).trim()) return res.status(400).json({ error: 'Title is required.' });
  if (!b.abstract || !String(b.abstract).trim()) return res.status(400).json({ error: 'Abstract is required.' });

  const clean = (v, max) => (v === undefined || v === null ? '' : String(v).slice(0, max));
  const sub = {
    id: 'sub_' + crypto.randomBytes(8).toString('hex'),
    category: clean(b.cat, 100) || 'Essays',
    title: clean(b.title, 500), author: clean(b.name, 200), email: clean(b.email, 500),
    dept: clean(b.dept, 200), abstract: clean(b.abstract, 4000),
    status: 'Submitted', date: new Date().toISOString(),
  };

  await withLock('submissions', async () => {
    const subs = readJSON('submissions', []);
    subs.unshift(sub);
    writeJSON('submissions', subs);
  });
  appendLog(`New journal submission: "${sub.title}" from ${sub.author}`);
  res.json({ ok: true });
});

app.get('/api/submissions', requireControlRole('admin', 'deputy'), (req, res) => {
  res.json({ submissions: readJSON('submissions', []) });
});

app.post('/api/submissions/:id/approve', csrfProtection, requireControlRole('admin', 'deputy'), async (req, res) => {
  const { id } = req.params;
  let published = null;

  await withLock('submissions', async () => {
    const subs = readJSON('submissions', []);
    const rec = subs.find(s => s.id === id);
    if (!rec) return;
    rec.status = 'Published';
    writeJSON('submissions', subs);
    published = rec;
  });

  if (published) {
    await withLock('content', async () => {
      const content = readJSON('content', {});
      if (!Array.isArray(content.journal)) content.journal = [];
      content.journal.unshift({
        id: 'j_' + crypto.randomBytes(6).toString('hex'),
        tag: published.category, title: published.title, sub: published.abstract.slice(0, 220),
        author: published.author, date: new Date().toISOString().slice(0, 10),
        readtime: `${Math.max(3, Math.round(published.abstract.split(/\s+/).length / 180))} min`,
        body: [published.abstract], placeholder: false,
      });
      writeJSON('content', content);
      bumpContentMeta();
    });
  }

  appendLog(`${req.session.name} approved & published submission ${id}`);
  res.json({ ok: true });
});

app.post('/api/submissions/:id/reject', csrfProtection, requireControlRole('admin', 'deputy'), async (req, res) => {
  const { id } = req.params;
  await withLock('submissions', async () => {
    const subs = readJSON('submissions', []);
    const rec = subs.find(s => s.id === id);
    if (rec) { rec.status = 'Rejected'; writeJSON('submissions', subs); }
  });
  appendLog(`${req.session.name} rejected submission ${id}`);
  res.json({ ok: true });
});

// =============================================================================
// CONTACT  (public submit; admin-only read — out of scope for deputy access)
// =============================================================================
app.post('/api/contact', csrfProtection, async (req, res) => {
  const b = req.body || {};
  if (!b.name || !b.email || !b.msg) return res.status(400).json({ error: 'Name, email, and message are required.' });
  const clean = (v, max) => String(v || '').slice(0, max);
  const msg = { id: 'msg_' + crypto.randomBytes(8).toString('hex'), name: clean(b.name, 200), email: clean(b.email, 500), cat: clean(b.cat, 100) || 'General', msg: clean(b.msg, 4000), date: new Date().toISOString() };
  await withLock('messages', async () => {
    const messages = readJSON('messages', []);
    messages.unshift(msg);
    writeJSON('messages', messages);
  });
  res.json({ ok: true });
});

app.get('/api/contact', requireControlRole('admin'), (req, res) => {
  res.json({ messages: readJSON('messages', []) });
});

// =============================================================================
// ACTIVITY LOG  (admin-only)
// =============================================================================
app.get('/api/log', requireControlRole('admin'), (req, res) => {
  res.json({ log: readJSON('log', []) });
});

// =============================================================================
// STAFF CONTROL-MODE SESSION  (the two-tier admin/deputy access system)
// =============================================================================
app.post('/api/control/login', csrfProtection, async (req, res) => {
  const name = String((req.body && req.body.name) || '').trim();
  const password = String((req.body && req.body.password) || '');
  const rateKey = `control:${req.ip}:${name.toLowerCase()}`;

  const limit = checkRateLimit(rateKey);
  if (limit.blocked) {
    return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  }
  if (!name || !password) {
    return res.status(400).json({ error: 'Name and access code are required.' });
  }

  const nameLower = name.toLowerCase();
  let role = null;
  let codeHash = null;
  let plainCode = null;
  if (ADMIN_NAMES.includes(nameLower) && (ADMIN_CODE_HASH || ADMIN_CODE)) {
    role = 'admin';
    codeHash = ADMIN_CODE_HASH;
    plainCode = ADMIN_CODE;
  } else if (nameLower === DEPUTY_NAME && (DEPUTY_CODE_HASH || DEPUTY_CODE)) {
    role = 'deputy';
    codeHash = DEPUTY_CODE_HASH;
    plainCode = DEPUTY_CODE;
  }

  const ok = role && (plainCode !== null
    ? password === plainCode
    : await bcryptCompare(password, codeHash));
  if (!ok) {
    recordFailure(rateKey);
    return res.status(401).json({ error: 'Invalid name or access code.' });
  }
  recordSuccess(rateKey);

  const { id } = createSession({ kind: 'control', role, name });
  setSessionCookie(res, id);
  appendLog(`${name} entered Control Mode (${role})`);
  res.json({ role, name });
});

app.post('/api/control/logout', csrfProtection, (req, res) => {
  if (req.cookies.sid) destroySession(req.cookies.sid);
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/control/me', (req, res) => {
  if (req.session && req.session.kind === 'control') {
    return res.json({ control: { role: req.session.role, name: req.session.name } });
  }
  res.json({ control: null });
});

// =============================================================================
// MEMBER ACCOUNTS  (username + password only, as the frontend expects)
// =============================================================================
app.post('/api/auth/signup', csrfProtection, async (req, res) => {
  const username = String((req.body && req.body.username) || '').trim();
  const password = String((req.body && req.body.password) || '');
  if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  let created = null;
  await withLock('users', async () => {
    const users = readJSON('users', []);
    if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
      created = { error: 'That username is already taken.' };
      return;
    }
    const passwordHash = await bcryptHash(password);
    const user = { username, passwordHash, role: 'applicant', createdAt: new Date().toISOString() };
    users.push(user);
    writeJSON('users', users);
    created = { username: user.username, role: user.role };
  });

  if (created.error) return res.status(409).json({ error: created.error });
  const { id } = createSession({ kind: 'user', username: created.username, role: created.role });
  setSessionCookie(res, id);
  res.json(created);
});

app.post('/api/auth/login', csrfProtection, async (req, res) => {
  const username = String((req.body && req.body.username) || '').trim();
  const password = String((req.body && req.body.password) || '');
  const rateKey = `user:${req.ip}:${username.toLowerCase()}`;

  const limit = checkRateLimit(rateKey);
  if (limit.blocked) return res.status(429).json({ error: 'Too many attempts. Try again later.' });

  const users = readJSON('users', []);
  const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
  const ok = user && await bcryptCompare(password, user.passwordHash);
  if (!ok) {
    recordFailure(rateKey);
    return res.status(401).json({ error: 'Invalid username or password.' });
  }
  recordSuccess(rateKey);

  const { id } = createSession({ kind: 'user', username: user.username, role: user.role });
  setSessionCookie(res, id);
  res.json({ username: user.username, role: user.role });
});

app.post('/api/auth/logout', csrfProtection, (req, res) => {
  if (req.cookies.sid) destroySession(req.cookies.sid);
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  if (req.session && req.session.kind === 'user') {
    return res.json({ user: { username: req.session.username, role: req.session.role } });
  }
  res.json({ user: null });
});

app.get('/api/health', async (req, res) => {
  try {
    await flushStore();
    res.json({ ok: true, database: process.env.DATABASE_URL ? 'neon' : 'local' });
  } catch (e) {
    res.status(503).json({ ok: false, database: 'error' });
  }
});

// SPA fallback: any non-API GET goes to index.html (the router is client-side).
app.get(/^\/(?!api\/).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// =============================================================================
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on the server.' });
});

const PORT = process.env.PORT || 3000;
(async () => {
  try {
    await initStore();
    app.listen(PORT, () => console.log(`CIVITAS backend listening on :${PORT}`));
  } catch (err) {
    console.error('[startup] Database initialization failed. Server not started.');
    process.exit(1);
  }
})();
