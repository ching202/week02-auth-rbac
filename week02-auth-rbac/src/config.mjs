export function readConfig(env = process.env) {
  const secret = env.SESSION_SECRET;
  if (!secret || !/^[a-f0-9]{64,}$/i.test(secret)) {
    throw new Error('SESSION_SECRET must be at least 32 random bytes encoded as hex. Run node scripts/setup.mjs.');
  }
  const origin = new URL(env.APP_ORIGIN || 'http://127.0.0.1:3000');
  if (!['http:', 'https:'].includes(origin.protocol) || origin.username || origin.password ||
      origin.pathname !== '/' || origin.search || origin.hash) {
    throw new Error('APP_ORIGIN must be an HTTP(S) origin with no path, credentials, query, or fragment.');
  }
  const local = ['127.0.0.1', 'localhost', '[::1]'].includes(origin.hostname);
  if (origin.protocol !== 'https:' && (env.NODE_ENV === 'production' || !local)) {
    throw new Error('HTTPS is required for production and non-loopback origins.');
  }
  const host = env.HOST || '127.0.0.1';
  if (origin.protocol === 'http:' && !['127.0.0.1', 'localhost', '::1'].includes(host)) {
    throw new Error('HTTP development mode must bind to a loopback interface.');
  }
  const port = Number(env.PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be 1–65535.');
  return {
    secret, origin: origin.origin, host, port,
    databasePath: env.DB_PATH || './data/gatehouse.sqlite',
    secureCookies: origin.protocol === 'https:',
  };
}
