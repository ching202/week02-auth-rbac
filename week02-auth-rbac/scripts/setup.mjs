import { writeFileSync, existsSync } from 'node:fs';
import { randomBytes, argon2 } from 'node:crypto';

if (typeof argon2 !== 'function') throw new Error('Install Node.js 24.7 or later in the 24.x series.');
if (existsSync('.env')) {
  console.log('.env already exists; no configuration was overwritten.');
} else {
  writeFileSync('.env', `SESSION_SECRET=${randomBytes(32).toString('hex')}\nAPP_ORIGIN=http://127.0.0.1:3000\nHOST=127.0.0.1\nPORT=3000\nDB_PATH=./data/gatehouse.sqlite\nNODE_ENV=development\n`, { flag: 'wx', mode: 0o600 });
  console.log('Created .env with a random session secret. Keep this file private.');
}
console.log('Next: node --env-file=.env scripts/create-admin.mjs');
console.log('Then: node --env-file=.env server.mjs');
