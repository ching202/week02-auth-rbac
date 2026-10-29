import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { createApplication } from '../src/app.mjs';
import { hashPassword, verifyPassword, tokenHash } from '../src/auth.mjs';

const PASSWORD = 'Testing only! password 2026';

async function fixture(t, overrides = {}) {
  const app = await createApplication({ secret: randomBytes(32).toString('hex'), ...overrides });
  const base = await app.listen();
  t.after(() => app.close());
  function client() {
    return {
      cookie: '', csrf: '',
      async call(path, { method = 'GET', body, headers = {}, csrf = true, raw } = {}) {
        const requestHeaders = { ...headers };
        if (this.cookie) requestHeaders.Cookie = this.cookie;
        if (method === 'POST') {
          requestHeaders.Origin ??= base;
          requestHeaders['Content-Type'] ??= 'application/json';
          if (csrf) requestHeaders['X-CSRF-Token'] = this.csrf;
        }
        const response = await fetch(base + path, {
          method, headers: requestHeaders, body: method === 'POST' ? raw ?? JSON.stringify(body ?? {}) : undefined,
        });
        const setCookie = response.headers.get('set-cookie');
        if (setCookie) this.cookie = setCookie.split(';')[0];
        const text = await response.text();
        let data;
        try { data = JSON.parse(text); } catch { data = text; }
        if (data.csrfToken) this.csrf = data.csrfToken;
        return { status: response.status, headers: response.headers, data };
      },
      async bootstrap() { return this.call('/api/session'); },
      async register(username = 'member', password = PASSWORD) {
        await this.bootstrap();
        return this.call('/api/register', { method: 'POST', body: { username, password } });
      },
      async login(username = 'member', password = PASSWORD) {
        return this.call('/api/login', { method: 'POST', body: { username, password } });
      },
    };
  }
  return { app, base, client };
}

test('registration stores a salted Argon2id hash and returns only public fields', async (t) => {
  const { app, client } = await fixture(t);
  const browser = client();
  const result = await browser.register();
  assert.equal(result.status, 201);
  assert.equal(result.data.user.role, 'User');
  assert.deepEqual(Object.keys(result.data.user).sort(), ['createdAt', 'id', 'role', 'username']);
  const row = app.db.prepare('SELECT * FROM users').get();
  assert.match(row.password_hash, /^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
  assert.ok(!row.password_hash.includes(PASSWORD));
  assert.equal(await verifyPassword(PASSWORD, row.password_hash), true);
  const secondHash = await hashPassword(PASSWORD);
  assert.notEqual(secondHash, row.password_hash);
  assert.equal(await verifyPassword('wrong long password', row.password_hash), false);
});

test('successful login rotates the anonymous session and grants profile access', async (t) => {
  const { client, app } = await fixture(t);
  const browser = client();
  await browser.register('Member');
  const oldCookie = browser.cookie;
  const oldCsrf = browser.csrf;
  assert.equal((await browser.login('MEMBER')).status, 200);
  assert.notEqual(browser.cookie, oldCookie);
  assert.notEqual(browser.csrf, oldCsrf);
  const profile = await browser.call('/api/profile');
  assert.equal(profile.status, 200);
  assert.equal(profile.data.user.username, 'member');
  assert.equal(app.db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 1);
  const replay = client(); replay.cookie = oldCookie;
  assert.equal((await replay.call('/api/profile')).status, 401);
});

test('wrong password and unknown username return identical generic 401 responses', async (t) => {
  const { client } = await fixture(t);
  const browser = client();
  await browser.register();
  const wrong = await browser.login('member', 'incorrect password!');
  const unknown = await browser.login('unknown', 'incorrect password!');
  assert.equal(wrong.status, 401);
  assert.equal(unknown.status, 401);
  assert.deepEqual(wrong.data, { error: 'Invalid username or password.' });
  assert.deepEqual(wrong.data, unknown.data);
});

test('logout revokes the server session; replaying its old cookie is rejected', async (t) => {
  const { app, client } = await fixture(t);
  const browser = client();
  await browser.register(); await browser.login();
  const stolenCookie = browser.cookie;
  const oldCsrf = browser.csrf;
  const logout = await browser.call('/api/logout', { method: 'POST' });
  assert.equal(logout.status, 200);
  assert.match(logout.headers.get('set-cookie'), /Max-Age=0/);
  assert.equal(app.db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 0);
  const replay = client(); replay.cookie = stolenCookie; replay.csrf = oldCsrf;
  assert.equal((await replay.call('/api/profile')).status, 401);
  assert.equal((await replay.call('/api/logout', { method: 'POST' })).status, 401);
});

test('anonymous callers receive 401 on both protected resources and 200 on public', async (t) => {
  const { client } = await fixture(t);
  const browser = client();
  assert.equal((await browser.call('/api/public')).status, 200);
  assert.equal((await browser.call('/api/profile')).status, 401);
  assert.equal((await browser.call('/api/admin/users')).status, 401);
});

test('standard User receives 200 for the dashboard and 403 for the Admin API', async (t) => {
  const { client } = await fixture(t);
  const browser = client();
  await browser.register(); await browser.login();
  assert.equal((await browser.call('/api/profile')).status, 200);
  const admin = await browser.call('/api/admin/users');
  assert.equal(admin.status, 403);
  assert.deepEqual(admin.data, { error: 'Admin access required.' });
});

test('a trusted Admin can read both resources; the directory strips all hashes', async (t) => {
  const { app, client } = await fixture(t);
  app.db.prepare("INSERT INTO users(username, password_hash, role, created_at) VALUES (?, ?, 'Admin', ?)")
    .run('administrator', await hashPassword(PASSWORD), Date.now());
  const browser = client();
  await browser.bootstrap(); await browser.login('administrator');
  assert.equal((await browser.call('/api/profile')).status, 200);
  const directory = await browser.call('/api/admin/users');
  assert.equal(directory.status, 200);
  assert.equal(directory.data.total, 1);
  assert.equal(directory.data.users[0].role, 'Admin');
  assert.ok(!JSON.stringify(directory.data).includes('password'));
  assert.ok(!JSON.stringify(directory.data).includes('$argon2'));
});

test('role changes take effect on the very next request of an existing session', async (t) => {
  const { app, client } = await fixture(t);
  const browser = client();
  await browser.register(); await browser.login();
  app.db.prepare("UPDATE users SET role = 'Admin' WHERE username = ?").run('member');
  assert.equal((await browser.call('/api/admin/users')).status, 200);
  app.db.prepare("UPDATE users SET role = 'User' WHERE username = ?").run('member');
  assert.equal((await browser.call('/api/admin/users')).status, 403);
});

test('public registration rejects injected role and privilege fields', async (t) => {
  const { app, client } = await fixture(t);
  const browser = client(); await browser.bootstrap();
  for (const field of [{ role: 'Admin' }, { isAdmin: true }, { user_id: 1 }]) {
    const result = await browser.call('/api/register', { method: 'POST', body: { username: 'intruder', password: PASSWORD, ...field } });
    assert.equal(result.status, 400);
  }
  assert.equal(app.db.prepare('SELECT COUNT(*) AS n FROM users').get().n, 0);
});

test('empty and malformed credentials fail server validation without creating users', async (t) => {
  const { app, client } = await fixture(t);
  const browser = client(); await browser.bootstrap();
  const bodies = [{}, { username: '', password: '' }, { username: 'member', password: 'short' },
    { username: ['member'], password: PASSWORD }, { username: 'member', password: 12 }, [], null];
  for (const body of bodies) {
    assert.equal((await browser.call('/api/register', { method: 'POST', body })).status, 400);
  }
  assert.equal(app.db.prepare('SELECT COUNT(*) AS n FROM users').get().n, 0);
});

test('SQL-like usernames fail safely; SQL and special characters in passwords work', async (t) => {
  const { client, app } = await fixture(t);
  const browser = client(); await browser.bootstrap();
  assert.equal((await browser.call('/api/register', { method: 'POST', body: { username: "' OR 1=1 --", password: PASSWORD } })).status, 400);
  const password = ` spaces ' OR 1=1; -- <script>alert(1)</script> 🔑 `;
  assert.equal((await browser.register('symbols', password)).status, 201);
  assert.equal((await browser.login('symbols', password)).status, 200);
  assert.equal((await browser.call('/api/profile')).status, 200);
  assert.equal(app.db.prepare('SELECT COUNT(*) AS n FROM users').get().n, 1);
});

test('duplicate usernames are case-insensitive and never overwrite the existing hash', async (t) => {
  const { client, app } = await fixture(t);
  const browser = client(); await browser.register('member');
  const original = app.db.prepare('SELECT password_hash FROM users').get().password_hash;
  assert.equal((await browser.register('MEMBER', 'another password 2026!')).status, 409);
  assert.equal(app.db.prepare('SELECT password_hash FROM users').get().password_hash, original);
});

test('CSRF rejects missing tokens, incorrect tokens, cross-origin and missing Origin', async (t) => {
  const { client, base } = await fixture(t);
  const browser = client(); await browser.bootstrap();
  const body = { username: 'member', password: PASSWORD };
  assert.equal((await browser.call('/api/register', { method: 'POST', body, csrf: false })).status, 403);
  assert.equal((await browser.call('/api/register', { method: 'POST', body, csrf: false, headers: { 'X-CSRF-Token': 'forged' } })).status, 403);
  assert.equal((await browser.call('/api/register', { method: 'POST', body, headers: { Origin: 'https://attacker.example' } })).status, 403);
  const missingOrigin = await fetch(base + '/api/register', { method: 'POST', headers: { Cookie: browser.cookie, 'Content-Type': 'application/json', 'X-CSRF-Token': browser.csrf }, body: JSON.stringify(body) });
  assert.equal(missingOrigin.status, 403);
  await missingOrigin.text();
});

test('one session cannot reuse another session’s CSRF token', async (t) => {
  const { client } = await fixture(t);
  const first = client(); const second = client();
  await first.bootstrap(); await second.bootstrap();
  second.csrf = first.csrf;
  assert.equal((await second.call('/api/register', { method: 'POST', body: { username: 'member', password: PASSWORD } })).status, 403);
});

test('CSRF enforcement also protects logout', async (t) => {
  const { client } = await fixture(t);
  const browser = client(); await browser.register(); await browser.login();
  assert.equal((await browser.call('/api/logout', { method: 'POST', csrf: false })).status, 403);
  assert.equal((await browser.call('/api/profile')).status, 200);
});

test('malformed JSON, unsupported media, and oversized bodies are clean errors', async (t) => {
  const { client } = await fixture(t);
  const browser = client(); await browser.bootstrap();
  assert.equal((await browser.call('/api/register', { method: 'POST', raw: '{' })).status, 400);
  assert.equal((await browser.call('/api/register', { method: 'POST', headers: { 'Content-Type': 'text/plain' } })).status, 415);
  assert.equal((await browser.call('/api/register', { method: 'POST', raw: JSON.stringify({ data: 'x'.repeat(9000) }) })).status, 413);
  assert.equal((await browser.call('/api/public')).status, 200);
});

test('forged, malformed, and duplicate session cookies never authenticate', async (t) => {
  const { client } = await fixture(t);
  const browser = client();
  for (const cookie of ['rbac_sid=Admin', 'rbac_sid=' + randomBytes(32).toString('base64url'), 'rbac_sid=a; rbac_sid=b']) {
    browser.cookie = cookie;
    assert.equal((await browser.call('/api/profile')).status, 401);
  }
});

test('sessions are stored as hashes and expire at the server’s absolute deadline', async (t) => {
  let clock = Date.now();
  const { app, client } = await fixture(t, { now: () => clock, sessionSeconds: 60 });
  const browser = client(); await browser.register(); await browser.login();
  const rawToken = browser.cookie.split('=')[1];
  const stored = app.db.prepare('SELECT * FROM sessions').get();
  assert.equal(stored.token_hash, tokenHash(rawToken));
  assert.notEqual(stored.token_hash, rawToken);
  clock += 60_000;
  assert.equal((await browser.call('/api/profile')).status, 401);
});

test('deleting an account invalidates its sessions through foreign-key cascade', async (t) => {
  const { app, client } = await fixture(t);
  const browser = client(); await browser.register(); await browser.login();
  app.db.prepare('DELETE FROM users WHERE username = ?').run('member');
  assert.equal((await browser.call('/api/profile')).status, 401);
  assert.equal(app.db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 0);
});

test('account throttling returns 429 and Retry-After, then resets after the window', async (t) => {
  let clock = Date.now();
  const { client } = await fixture(t, { now: () => clock });
  const browser = client(); await browser.bootstrap();
  for (let i = 0; i < 10; i++) assert.equal((await browser.login('unknown')).status, 401);
  const blocked = await browser.login('unknown');
  assert.equal(blocked.status, 429);
  assert.ok(Number(blocked.headers.get('retry-after')) > 0);
  clock += 301_000;
  assert.equal((await browser.login('unknown')).status, 401);
});

test('IP throttling cannot be bypassed by changing usernames or forwarding headers', async (t) => {
  const { client } = await fixture(t);
  const browser = client(); await browser.bootstrap();
  for (let i = 0; i < 30; i++) {
    const result = await browser.call('/api/login', { method: 'POST', body: { username: `unknown${i}`, password: PASSWORD }, headers: { 'X-Forwarded-For': `10.0.0.${i}` } });
    assert.equal(result.status, 401);
  }
  assert.equal((await browser.login('different')).status, 429);
});

test('cookies and response headers apply the intended browser protections', async (t) => {
  const { client } = await fixture(t, { secureCookies: true });
  const result = await client().bootstrap();
  const cookie = result.headers.get('set-cookie');
  for (const attribute of ['HttpOnly', 'SameSite=Strict', 'Secure', 'Max-Age=1800']) assert.ok(cookie.includes(attribute));
  assert.equal(result.headers.get('cache-control'), 'no-store');
  assert.equal(result.headers.get('x-content-type-options'), 'nosniff');
  assert.match(result.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.match(result.headers.get('strict-transport-security'), /max-age=/);
  assert.equal(result.headers.get('access-control-allow-origin'), null);
});

test('server does not expose environment, database, source files or unrecognized hosts', async (t) => {
  const { client, base } = await fixture(t);
  const browser = client();
  for (const path of ['/.env', '/data/gatehouse.sqlite', '/src/auth.mjs', '/does-not-exist']) {
    assert.equal((await browser.call(path)).status, 404);
  }
  // Fetch normalizes Host. Use a raw HTTP request to actually send the hostile value.
  const hostileHost = await new Promise((resolve, reject) => {
    const req = httpRequest(base + '/api/public', { headers: { Host: 'attacker.example' } }, (res) => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject); req.end();
  });
  assert.equal(hostileHost, 400);
  assert.equal((await browser.call('/api/logout')).status, 405);
});
