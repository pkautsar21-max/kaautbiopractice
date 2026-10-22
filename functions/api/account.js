import { json, handle, readBody, HttpError, USERNAME_RE, hashPassword, verifyPassword, newSession, bearer, sha256 } from '../_lib/util.js';

const MAX_FAILS = 8, LOCK_MS = 15 * 60 * 1000;

export const onRequestPost = handle(async ({ request, env }) => {
  const db = env.DB, b = await readBody(request);
  if (b.action === 'register') return register(db, b);
  if (b.action === 'login') return login(db, b);
  if (b.action === 'logout') {
    const t = bearer(request);
    if (t) await db.prepare('DELETE FROM bio_sessions WHERE token_hash = ?').bind(await sha256(t)).run();
    return json({ ok: true });
  }
  throw new HttpError(400, 'Bad request.');
});

function readCreds(b) {
  const username = String(b.username ?? '').trim().toLowerCase();
  const password = String(b.password ?? '');
  return { username, password };
}

async function register(db, b) {
  const { username, password } = readCreds(b);
  if (!USERNAME_RE.test(username)) throw new HttpError(400, 'Usernames need 3–20 letters, numbers, dots, dashes or underscores.');
  if (password.length < 6 || password.length > 200) throw new HttpError(400, 'Passwords need at least 6 characters.');
  if (await db.prepare('SELECT 1 FROM bio_users WHERE username = ?').bind(username).first())
    throw new HttpError(409, 'That username is taken. Try another one.');
  const id = crypto.randomUUID();
  try {
    await db.prepare('INSERT INTO bio_users (id, username, pass, created_at) VALUES (?, ?, ?, ?)')
      .bind(id, username, await hashPassword(password), Date.now()).run();
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) throw new HttpError(409, 'That username is taken. Try another one.');
    throw e;
  }
  return json({ username, token: await newSession(db, id) });
}

async function login(db, b) {
  const { username, password } = readCreds(b);
  const bad = new HttpError(401, 'Wrong username or password.');
  if (!USERNAME_RE.test(username) || !password) throw bad;
  const user = await db.prepare('SELECT * FROM bio_users WHERE username = ?').bind(username).first();
  if (!user) { await hashPassword(password); throw bad; } // keep timing similar
  if (user.locked_until > Date.now()) throw new HttpError(429, 'Too many wrong tries. Please wait 15 minutes and try again.');
  if (!(await verifyPassword(password, user.pass))) {
    const fails = user.fails + 1;
    await db.prepare('UPDATE bio_users SET fails = ?, locked_until = ? WHERE id = ?')
      .bind(fails >= MAX_FAILS ? 0 : fails, fails >= MAX_FAILS ? Date.now() + LOCK_MS : 0, user.id).run();
    throw bad;
  }
  if (user.fails) await db.prepare('UPDATE bio_users SET fails = 0, locked_until = 0 WHERE id = ?').bind(user.id).run();
  return json({ username: user.username, token: await newSession(db, user.id) });
}
