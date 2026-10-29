import { DatabaseSync } from 'node:sqlite';
import { readConfig } from '../src/config.mjs';

try {
  const db = new DatabaseSync(readConfig().databasePath, { readOnly: true });
  console.table(db.prepare('SELECT id, username, role, password_hash FROM users ORDER BY id').all());
  console.log('Each password_hash should begin with $argon2id$v=19$m=19456,t=2,p=1$.');
  console.log('Use throwaway accounts for the recording. Never publish a real account database.');
  db.close();
} catch (error) {
  console.error(`Inspection failed: ${error.message}`);
  process.exitCode = 1;
}
