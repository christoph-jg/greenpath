import { getSession, verifyPassword, hashPassword } from '../_lib/auth.js';

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status, headers: { 'Content-Type': 'application/json' },
  });
}

// Change the signed-in user's own password.
export async function onRequestPost({ request, env }) {
  if (!env.DB || !env.SESSION_SECRET) return json({ error: 'Portal is not configured yet.' }, 503);

  const session = await getSession(request, env);
  if (!session) return json({ error: 'unauthorized' }, 401);

  let b;
  try { b = await request.json(); } catch { return json({ error: 'Bad request' }, 400); }
  const current = b.currentPassword || '';
  const next = b.newPassword || '';

  if (next.length < 8) return json({ error: 'New password must be at least 8 characters.' }, 400);

  const user = await env.DB
    .prepare('SELECT username, password FROM users WHERE username = ?')
    .bind(session.u).first();
  if (!user) return json({ error: 'Account not found.' }, 404);

  if (!(await verifyPassword(current, user.password))) {
    return json({ error: 'Your current password is incorrect.' }, 403);
  }
  if (await verifyPassword(next, user.password)) {
    return json({ error: 'New password must be different from your current one.' }, 400);
  }

  const hash = await hashPassword(next);
  await env.DB.prepare('UPDATE users SET password = ? WHERE username = ?')
    .bind(hash, session.u).run();
  return json({ ok: true });
}
