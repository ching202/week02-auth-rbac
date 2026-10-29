import { createInterface } from 'node:readline/promises';
import { Writable } from 'node:stream';
import { stdin, stdout } from 'node:process';
import { readConfig } from '../src/config.mjs';
import { openDatabase } from '../src/db.mjs';
import { hashPassword, validateCredentials } from '../src/auth.mjs';

if (!stdin.isTTY) {
  console.error('Run this command in an interactive terminal. Password input is hidden.');
  process.exit(1);
}
const config = readConfig();
let muted = false;
const output = new Writable({ write(chunk, encoding, callback) { if (!muted) stdout.write(chunk, encoding); callback(); } });
const rl = createInterface({ input: stdin, output, terminal: true });
let db;
try {
  const username = await rl.question('New Admin username: ');
  stdout.write('Password (12–128 characters; hidden): ');
  muted = true;
  const password = await rl.question('');
  muted = false;
  stdout.write('\nConfirm password (hidden): ');
  muted = true;
  const confirmation = await rl.question('');
  muted = false;
  stdout.write('\n');
  if (password !== confirmation) throw new Error('Passwords do not match.');
  const credentials = validateCredentials({ username, password });
  db = openDatabase(config.databasePath);
  const result = db.prepare(`INSERT INTO users(username, password_hash, role, created_at)
    VALUES (?, ?, 'Admin', ?) ON CONFLICT(username) DO NOTHING`)
    .run(credentials.username, await hashPassword(credentials.password), Date.now());
  if (!result.changes) throw new Error('Username already exists. Choose a new Admin username; existing accounts are never promoted by this command.');
  console.log(`Admin account '${credentials.username}' created. Sign in through the app.`);
} catch (error) {
  muted = false;
  console.error(`Admin creation failed: ${error.message}`);
  process.exitCode = 1;
} finally { rl.close(); db?.close(); }
