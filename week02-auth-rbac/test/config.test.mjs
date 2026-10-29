import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readConfig } from '../src/config.mjs';

const settings = () => ({ SESSION_SECRET: randomBytes(32).toString('hex') });
test('missing and placeholder secrets fail closed', () => {
  assert.throws(() => readConfig({}), /SESSION_SECRET/);
  assert.throws(() => readConfig({ SESSION_SECRET: 'replace-with-at-least-32-random-bytes' }), /SESSION_SECRET/);
});
test('production and non-loopback origins require HTTPS', () => {
  assert.throws(() => readConfig({ ...settings(), NODE_ENV: 'production' }), /HTTPS/);
  assert.throws(() => readConfig({ ...settings(), APP_ORIGIN: 'http://example.com' }), /HTTPS/);
  const config = readConfig({ ...settings(), NODE_ENV: 'production', APP_ORIGIN: 'https://example.com' });
  assert.equal(config.secureCookies, true);
});
test('HTTP development cannot bind to a public interface', () => {
  assert.throws(() => readConfig({ ...settings(), HOST: '0.0.0.0' }), /loopback/);
  assert.equal(readConfig(settings()).host, '127.0.0.1');
});
test('origins reject paths, credentials, fragments and non-HTTP protocols', () => {
  for (const origin of ['http://127.0.0.1:3000/path', 'https://u:p@example.com', 'https://example.com/#frag', 'file:///tmp']) {
    assert.throws(() => readConfig({ ...settings(), APP_ORIGIN: origin }), /APP_ORIGIN/);
  }
});
test('ports reject invalid configuration', () => {
  for (const port of ['0', '-1', '1.5', '65536', 'NaN']) assert.throws(() => readConfig({ ...settings(), PORT: port }), /PORT/);
});
