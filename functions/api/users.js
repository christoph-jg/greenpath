import { getSession, hashPassword } from '../_lib/auth.js';

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status, headers: { 'Content-Type': 'application/json' },
  });
}

async function requireAdmin(request, env) {
  if (!env.DB || !env.SESSION_SECRET) return null;
  const s = await getSession(request, env);
  if (!s || s.r !== 'admin') return null;
  return s;
}

// List users (admin only)
export async function onRequestGet({ request, env }) {
  if (!(await requireAdmin(request, env))) return json({ error: 'forbidden' }, 403);
  const { results } = await env.DB
    .prepare('SELECT id, username, role, created_at FROM users ORDER BY id').all();
  return json({ users: results });
}

// Create a user (admin only)
export async function onRequestPost({ request, env }) {
  if (!(await requireAdmin(request, env))) return json({ error: 'forbidden' }, 403);

  let b;
  try { b = await request.json(); } catch { return json({ error: 'Bad request' }, 400); }
  const username = (b.username || '').trim();
  const password = b.password || '';
  const role = b.role === 'admin' ? 'admin' : 'instructor';

  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
    return json({ error: 'Username must be 3–32 chars (letters, numbers, _ . -).' }, 400);
  }
  if (password.length < 8) {
    return json({ error: 'Password must be at least 8 characters.' }, 400);
  }

  const exists = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (exists) return json({ error: 'That username already exists.' }, 409);

  const hash = await hashPassword(password);
  await env.DB.prepare('INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)')
    .bind(username, hash, role, Date.now()).run();
  return json({ ok: true });
}

// Delete a user (admin only): /api/users?username=foo
export async function onRequestDelete({ request, env }) {
  const admin = await requireAdmin(request, env);
  if (!admin) return json({ error: 'forbidden' }, 403);

  const username = new URL(request.url).searchParams.get('username');
  if (!username) return json({ error: 'username required' }, 400);
  if (username === admin.u) return json({ error: "You can't delete your own account." }, 400);

  await env.DB.prepare('DELETE FROM users WHERE username = ?').bind(username).run();
  return json({ ok: true });
}
