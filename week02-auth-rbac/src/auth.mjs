import { argon2, randomBytes, createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const derive = promisify(argon2);
const parameters = { memory: 19456, passes: 2, parallelism: 1, tagLength: 32 };
const prefix = '$argon2id$v=19$m=19456,t=2,p=1$';
const b64 = (value) => value.toString('base64').replace(/=+$/, '');

export class HttpError extends Error {
  constructor(status, message, headers = {}) {
    super(message);
    this.status = status;
    this.headers = headers;
  }
}

export function validateCredentials(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new HttpError(400, 'Send a JSON object with username and password.');
  }
  if (Object.keys(body).some((key) => !['username', 'password'].includes(key))) {
    throw new HttpError(400, 'Only username and password are accepted.');
  }
  const { username, password } = body;
  if (typeof username !== 'string' || !/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
    throw new HttpError(400, 'Username must be 3–32 letters, numbers, or underscores.');
  }
  if (typeof password !== 'string' || password.length < 12 || password.length > 128) {
    throw new HttpError(400, 'Password must be 12–128 characters.');
  }
  // Passwords are never trimmed, normalized, logged, or silently truncated.
  return { username: username.toLowerCase(), password };
}

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = await derive('argon2id', { ...parameters, message: password, nonce: salt });
  return `${prefix}${b64(salt)}$${b64(hash)}`;
}

export async function verifyPassword(password, encoded) {
  // Only accept our bounded parameters; never let stored metadata allocate arbitrary memory.
  if (typeof encoded !== 'string' || !encoded.startsWith(prefix)) return false;
  const [saltText, hashText, extra] = encoded.slice(prefix.length).split('$');
  if (!saltText || !hashText || extra !== undefined) return false;
  const salt = Buffer.from(saltText, 'base64');
  const expected = Buffer.from(hashText, 'base64');
  if (salt.length !== 16 || expected.length !== 32) return false;
  const actual = await derive('argon2id', { ...parameters, message: password, nonce: salt });
  return timingSafeEqual(actual, expected);
}

export const newToken = () => randomBytes(32).toString('base64url');
// Fast hashing is appropriate for random 256-bit tokens, NOT human passwords.
export const tokenHash = (token) => createHash('sha256').update(token).digest('hex');
export const csrfFor = (secret, token) => createHmac('sha256', secret).update(`csrf:${token}`).digest('base64url');
export const rateKey = (secret, value) => createHmac('sha256', secret).update(`rate:${value}`).digest('hex');

export function equalText(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string') return false;
  const a = Buffer.from(actual);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function readSessionCookie(header = '') {
  const values = header.split(';').map((part) => part.trim()).filter((part) => part.startsWith('rbac_sid='));
  if (values.length !== 1) return null;
  const value = values[0].slice('rbac_sid='.length);
  return /^[A-Za-z0-9_-]{43}$/.test(value) ? value : null;
}

export function requireUser(session) {
  if (!session?.user) throw new HttpError(401, 'Authentication required.');
  return session.user;
}

export function requireAdmin(session) {
  const user = requireUser(session);
  if (user.role !== 'Admin') throw new HttpError(403, 'Admin access required.');
  return user;
}
