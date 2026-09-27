const { Pool } = require('pg');

const hasNeon = !!process.env.DATABASE_URL;
const cache = new Map();
const dirty = new Set();
const writeChains = new Map();
let initialized = false;
let initPromise = null;
let pool = null;

function fallbackValue(name, fallback) {
  return typeof fallback === 'function' ? fallback() : fallback;
}

function readJSON(name, fallback) {
  if (cache.has(name)) return cache.get(name);
  return fallbackValue(name, fallback);
}

function queueWrite(name, value) {
  cache.set(name, value);
  dirty.add(name);
  if (!initialized || !pool) return;
  const previous = writeChains.get(name) || Promise.resolve();
  const next = previous.then(async () => {
    await pool.query(
      `INSERT INTO civitas_store (name, value, updated_at)
       VALUES ($1, $2::jsonb, NOW())
       ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      [name, JSON.stringify(value)]
    );
    dirty.delete(name);
  }).catch(err => {
    console.error(`[store] failed to persist ${name}:`, err.message);
    throw err;
  });
  writeChains.set(name, next);
}

function writeJSON(name, value) {
  queueWrite(name, value);
}

async function flushStore() {
  await Promise.all([...writeChains.values()]);
}

const locks = new Map();
async function withLock(name, fn) {
  const prev = locks.get(name) || Promise.resolve();
  let release;
  const next = new Promise(res => { release = res; });
  locks.set(name, prev.then(() => next));
  await prev;
  try {
    return await fn();
  } finally {
    release();
    // Ensure writes made inside this lock have reached Neon before callers
    // relying on the save get a successful response.
    try { await flushStore(); } catch (_) {}
  }
}

async function initStore() {
  if (initialized) return;
  if (initPromise) return initPromise;
  initPromise = (async () => {
    if (!hasNeon) {
      initialized = true;
      console.warn('[store] DATABASE_URL is not set; using local JSON fallback. Data will not survive Render restarts.');
      return;
    }

    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 5,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
    });

    await pool.query(`
      CREATE TABLE IF NOT EXISTS civitas_store (
        name TEXT PRIMARY KEY,
        value JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    const result = await pool.query('SELECT name, value FROM civitas_store');
    for (const row of result.rows) cache.set(row.name, row.value);

    // Any writes that happened before initialization (for example during
    // module loading) should be persisted, but database values take priority
    // when they already exist.
    for (const name of dirty) {
      if (!result.rows.some(r => r.name === name)) {
        await pool.query(
          `INSERT INTO civitas_store (name, value, updated_at) VALUES ($1, $2::jsonb, NOW()) ON CONFLICT (name) DO NOTHING`,
          [name, JSON.stringify(cache.get(name))]
        );
      }
    }
    dirty.clear();
    initialized = true;
    console.log('[store] Neon PostgreSQL connected and civitas_store is ready.');
  })().catch(err => {
    console.error('[store] Neon initialization failed:', err.message);
    process.exitCode = 1;
    throw err;
  });
  return initPromise;
}

async function closeStore() {
  await flushStore().catch(() => {});
  if (pool) await pool.end();
}

module.exports = { readJSON, writeJSON, withLock, flushStore, initStore, closeStore, get pool(){ return pool; } };
