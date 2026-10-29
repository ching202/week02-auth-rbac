import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { openDatabase, publicUser } from './db.mjs';
import {
  HttpError, validateCredentials, hashPassword, verifyPassword, newToken, tokenHash,
  csrfFor, rateKey, equalText, readSessionCookie, requireUser, requireAdmin,
} from './auth.mjs';

const SESSION_SECONDS = 30 * 60;
const WINDOW_MS = 5 * 60 * 1000;
const MAX_BODY = 8192;
const staticFiles = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/styles.css', ['styles.css', 'text/css; charset=utf-8']],
  ['/favicon.svg', ['favicon.svg', 'image/svg+xml']],
]);

function readJson(req) {
  if ((req.headers['content-type'] || '').split(';')[0].trim().toLowerCase() !== 'application/json') {
    req.resume();
    throw new HttpError(415, 'Content-Type must be application/json.');
  }
  return new Promise((resolve, reject) => {
    let bytes = 0;
    let oversized = false;
    const chunks = [];
    req.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_BODY) {
        oversized = true;
        chunks.length = 0;
        reject(new HttpError(413, 'Request body is too large.'));
      } else if (!oversized) chunks.push(chunk);
    });
    req.on('end', () => {
      if (oversized) return;
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(new HttpError(400, 'Invalid JSON.')); }
    });
    req.on('error', reject);
    req.on('aborted', () => reject(new HttpError(400, 'Request interrupted.')));
  });
}

export async function createApplication(options) {
  const {
    databasePath = ':memory:', secret, secureCookies = false,
    sessionSeconds = SESSION_SECONDS, now = Date.now,
  } = options;
  if (typeof secret !== 'string' || secret.length < 32) throw new Error('A session secret is required.');
  const db = openDatabase(databasePath);
  let origin = options.origin || null;
  let hashing = 0;
  let lastCleanup = 0;
  const assets = new Map(await Promise.all([...staticFiles].map(async ([path, [file, mime]]) =>
    [path, { content: await readFile(new URL(`../public/${file}`, import.meta.url)), mime }])));
  // Unknown usernames still incur one real password verification.
  const dummyHash = await hashPassword(newToken());

  const json = (res, status, body, headers = {}) => {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
    res.end(JSON.stringify(body));
  };
  const cookie = (token, age = sessionSeconds) =>
    `rbac_sid=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${secureCookies ? '; Secure' : ''}`;
  const revoke = (token) => {
    if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash(token));
  };
  const newSession = (res, userId = null, oldToken = null) => {
    const token = newToken();
    db.exec('BEGIN IMMEDIATE');
    try {
      revoke(oldToken);
      db.prepare('INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?, ?, ?)')
        .run(tokenHash(token), userId, now() + sessionSeconds * 1000);
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
    res.setHeader('Set-Cookie', cookie(token));
    return token;
  };
  const findSession = (token) => {
    if (!token) return null;
    // Roles come from users on EVERY request, never from the browser or a cached token claim.
    const row = db.prepare(`SELECT s.expires_at, u.id, u.username, u.role, u.created_at
      FROM sessions s LEFT JOIN users u ON s.user_id = u.id
      WHERE s.token_hash = ? AND s.expires_at > ?`).get(tokenHash(token), now());
    return row ? { user: row.id ? publicUser(row) : null, expiresAt: row.expires_at } : null;
  };
  const limit = (key, maximum) => {
    const bucket = rateKey(secret, key);
    // One atomic upsert avoids read/modify/write races across processes.
    const row = db.prepare(`INSERT INTO rate_limits(bucket, count, resets_at) VALUES (?, 1, ?)
      ON CONFLICT(bucket) DO UPDATE SET
        count = CASE WHEN resets_at <= ? THEN 1 ELSE count + 1 END,
        resets_at = CASE WHEN resets_at <= ? THEN excluded.resets_at ELSE resets_at END
      RETURNING count, resets_at`).get(bucket, now() + WINDOW_MS, now(), now());
    if (row.count > maximum) throw new HttpError(429, 'Too many attempts. Try again later.', {
      'Retry-After': String(Math.max(1, Math.ceil((row.resets_at - now()) / 1000))),
    });
  };
  const withHashSlot = async (fn) => {
    if (hashing >= 4) throw new HttpError(503, 'Authentication is busy. Try again shortly.', { 'Retry-After': '1' });
    hashing++;
    try { return await fn(); } finally { hashing--; }
  };

  const server = createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    if (secureCookies) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    try {
      if (req.headers.host !== new URL(origin).host) throw new HttpError(400, 'Unrecognized host.');
      if (now() - lastCleanup > 60_000) {
        db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now());
        db.prepare('DELETE FROM rate_limits WHERE resets_at <= ?').run(now());
        lastCleanup = now();
      }
      const path = new URL(req.url, origin).pathname;
      if (req.method === 'GET' && assets.has(path)) {
        const { content, mime } = assets.get(path);
        res.writeHead(200, { 'Content-Type': mime });
        return res.end(content);
      }
      const token = readSessionCookie(req.headers.cookie);
      const session = findSession(token);
      const ip = req.socket.remoteAddress || 'unknown'; // Do not trust spoofable forwarded headers.
      if (req.method === 'GET' && path === '/api/public') {
        return json(res, 200, { message: 'Welcome to Gatehouse. This resource is public.', access: 'Public' });
      }
      if (req.method === 'GET' && path === '/api/session') {
        let activeToken = token;
        if (!session) {
          limit(`session:${ip}`, 120);
          activeToken = newSession(res);
        }
        return json(res, 200, { user: session?.user || null, csrfToken: csrfFor(secret, activeToken) });
      }
      if (req.method === 'GET' && path === '/api/profile') {
        const user = requireUser(session);
        return json(res, 200, { message: `Welcome, ${user.username}.`, user, expiresAt: session.expiresAt });
      }
      if (req.method === 'GET' && path === '/api/admin/users') {
        requireAdmin(session);
        const users = db.prepare('SELECT id, username, role, created_at FROM users ORDER BY id LIMIT 100').all().map(publicUser);
        const total = db.prepare('SELECT COUNT(*) AS total FROM users').get().total;
        return json(res, 200, { users, total, limit: 100 });
      }
      const actions = ['/api/register', '/api/login', '/api/logout'];
      if (actions.includes(path) && req.method !== 'POST') {
        throw new HttpError(405, 'Method not allowed.', { Allow: 'POST' });
      }
      if (req.method !== 'POST' || !actions.includes(path)) throw new HttpError(404, 'Resource not found.');
      // Authentication precedes CSRF on logout so anonymous requests get a clean 401.
      if (path === '/api/logout') requireUser(session);
      if (req.headers.origin !== origin || !session || !equalText(req.headers['x-csrf-token'], csrfFor(secret, token))) {
        throw new HttpError(403, 'Request verification failed. Refresh the page and try again.');
      }
      const body = await readJson(req);
      if (path === '/api/logout') {
        revoke(token);
        res.setHeader('Set-Cookie', cookie('', 0));
        return json(res, 200, { message: 'Signed out. Your session has been revoked.' });
      }
      limit(`auth:${ip}`, 30);
      const { username, password } = validateCredentials(body);
      limit(`account:${username}`, 10);
      if (path === '/api/register') {
        const passwordHash = await withHashSlot(() => hashPassword(password));
        // Public registration cannot assign a role. All SQL inputs use bound parameters.
        const result = db.prepare(`INSERT INTO users(username, password_hash, role, created_at)
          VALUES (?, ?, 'User', ?) ON CONFLICT(username) DO NOTHING`).run(username, passwordHash, now());
        if (result.changes === 0) throw new HttpError(409, 'Unable to register with those details.');
        const row = db.prepare('SELECT id, username, role, created_at FROM users WHERE id = ?').get(result.lastInsertRowid);
        return json(res, 201, { message: 'Account created. Sign in to continue.', user: publicUser(row) });
      }
      const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
      const valid = await withHashSlot(() => verifyPassword(password, row?.password_hash || dummyHash));
      if (!row || !valid) throw new HttpError(401, 'Invalid username or password.');
      const activeToken = newSession(res, row.id, token);
      return json(res, 200, { message: 'Signed in successfully.', user: publicUser(row), csrfToken: csrfFor(secret, activeToken) });
    } catch (error) {
      if (res.destroyed || res.writableEnded) return;
      if (error instanceof HttpError) return json(res, error.status, { error: error.message }, error.headers);
      // Log the error type only; never echo credentials, SQL, or stack traces to clients.
      console.error('Request failed:', error.name);
      json(res, 500, { error: 'Something went wrong. Please try again.' });
    }
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.maxHeadersCount = 40;
  return {
    db, server,
    async listen(port = 0, host = '127.0.0.1') {
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => { server.off('error', reject); resolve(); });
      });
      if (!origin) origin = `http://127.0.0.1:${server.address().port}`;
      return origin;
    },
    async close() {
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      db.close();
    },
  };
}
