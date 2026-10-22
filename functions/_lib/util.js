// Shared helpers for the Bio guide's /api routes.

export const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });

export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

export const handle = fn => async ctx => {
  try {
    if (!ctx.env.DB) throw new HttpError(500, 'Server isn’t set up yet (database missing).');
    return await fn(ctx);
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    console.error(e);
    return json({ error: 'Something went wrong on the server. Try again in a moment.' }, 500);
  }
};

export async function readBody(request) {
  const text = await request.text();
  if (text.length > 100000) throw new HttpError(413, 'That request was too big.');
  try { const b = JSON.parse(text || '{}'); return b && typeof b === 'object' ? b : {}; }
  catch { throw new HttpError(400, 'Bad request.'); }
}

/* ---------- crypto ---------- */
const enc = new TextEncoder();
const toHex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const fromHex = h => Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16));

export const randomHex = n => toHex(crypto.getRandomValues(new Uint8Array(n)));
export async function sha256(str) { return toHex(await crypto.subtle.digest('SHA-256', enc.encode(str))); }

// Cloudflare's free plan gives each request ~10 ms of CPU, so we use 50,000 PBKDF2 rounds.
// The round count is stored inside the hash, so it can be raised later without breaking old accounts.
const ITERATIONS = 50000;

async function derive(password, saltHex, iterations) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return toHex(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(saltHex), iterations }, key, 256));
}
export async function hashPassword(password) {
  const salt = randomHex(16);
  return `pbkdf2$${ITERATIONS}$${salt}$${await derive(password, salt, ITERATIONS)}`;
}
export async function verifyPassword(password, stored) {
  const [kind, it, salt, hash] = String(stored || '').split('$');
  const iterations = parseInt(it, 10);
  if (kind !== 'pbkdf2' || !(iterations >= 1000 && iterations <= 100000) || !salt || !hash) return false;
  const a = await derive(password, salt, iterations);
  if (a.length !== hash.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ hash.charCodeAt(i);
  return d === 0;
}

/* ---------- sessions ---------- */
export const USERNAME_RE = /^[a-z0-9_.-]{3,20}$/;
const SESSION_CAP = 10;

export const bearer = request => {
  const m = /^Bearer ([0-9a-f]{48})$/.exec(request.headers.get('authorization') || '');
  return m ? m[1] : null;
};

export async function newSession(db, userId) {
  const token = randomHex(24), now = Date.now();
  await db.batch([
    db.prepare('INSERT INTO bio_sessions (token_hash, user_id, created_at) VALUES (?, ?, ?)').bind(await sha256(token), userId, now),
    db.prepare(`DELETE FROM bio_sessions WHERE user_id = ? AND token_hash NOT IN
      (SELECT token_hash FROM bio_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT ${SESSION_CAP})`).bind(userId, userId),
  ]);
  return token;
}

export async function requireUser(db, request) {
  const token = bearer(request);
  const row = token && await db.prepare(
    'SELECT u.id, u.username FROM bio_sessions s JOIN bio_users u ON u.id = s.user_id WHERE s.token_hash = ?'
  ).bind(await sha256(token)).first();
  if (!row) throw new HttpError(401, 'Please log in again.');
  return row;
}
