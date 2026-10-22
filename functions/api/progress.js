import { json, handle, readBody, HttpError, requireUser } from '../_lib/util.js';

const KEY_RE = /^lo\d{1,2}$/;

// Accepts {lo8: {a: [true,false,...], t: 1700000000000}, ...} and drops anything malformed.
function clean(data) {
  const out = {};
  if (!data || typeof data !== 'object') return out;
  for (const [k, v] of Object.entries(data).slice(0, 30)) {
    if (!KEY_RE.test(k) || !v || !Array.isArray(v.a) || v.a.length > 100) continue;
    const t = Number.isFinite(v.t) ? Math.min(Math.max(Math.round(v.t), 0), 9e15) : 0;
    out[k] = { a: v.a.map(Boolean), t };
  }
  return out;
}

// Per chapter, the most recently changed copy wins. t = 0 marks old, untimed ticks, which are combined instead.
function merge(server, client) {
  const out = { ...server };
  for (const [k, c] of Object.entries(client)) {
    const s = server[k];
    if (!s) { out[k] = c.t === 0 ? { a: c.a, t: 1 } : c; continue; }
    if (c.t === 0) {
      const len = Math.max(s.a.length, c.a.length);
      out[k] = { a: Array.from({ length: len }, (_, i) => !!(s.a[i] || c.a[i])), t: Math.max(s.t, 1) };
    } else if (c.t > s.t) out[k] = c;
  }
  return out;
}

async function load(db, userId) {
  const row = await db.prepare('SELECT data FROM bio_progress WHERE user_id = ?').bind(userId).first();
  try { return clean(JSON.parse(row?.data || '{}')); } catch { return {}; }
}

export const onRequestGet = handle(async ({ request, env }) => {
  const user = await requireUser(env.DB, request);
  return json({ data: await load(env.DB, user.id) });
});

export const onRequestPost = handle(async ({ request, env }) => {
  const user = await requireUser(env.DB, request);
  const b = await readBody(request);
  if (!b.data || typeof b.data !== 'object') throw new HttpError(400, 'Bad request.');
  const merged = merge(await load(env.DB, user.id), clean(b.data));
  await env.DB.prepare(
    'INSERT INTO bio_progress (user_id, data, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at'
  ).bind(user.id, JSON.stringify(merged), Date.now()).run();
  return json({ data: merged });
});
