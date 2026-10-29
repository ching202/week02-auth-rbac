import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

export function openDatabase(path) {
  if (path !== ':memory:') mkdirSync(dirname(resolve(path)), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(path, { enableForeignKeyConstraints: true, timeout: 5000 });
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL COLLATE NOCASE UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'User' CHECK (role IN ('User', 'Admin')),
      created_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
    CREATE TABLE IF NOT EXISTS rate_limits (
      bucket TEXT PRIMARY KEY,
      count INTEGER NOT NULL,
      resets_at INTEGER NOT NULL
    ) STRICT;
  `);
  return db;
}

export function publicUser(row) {
  return { id: row.id, username: row.username, role: row.role, createdAt: row.created_at };
}
