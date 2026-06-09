import { verifyPassword, hashPassword, createToken, sessionCookie } from '../_lib/auth.js';

function json(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const { DB, SESSION_SECRET, BOOTSTRAP_USER, BOOTSTRAP_PASS } = env;

  if (!DB || !SESSION_SECRET) {
    return json({ error: 'Portal is not configured yet. See SETUP-PORTAL.md.' }, 503);
  }

  let body;
  try { body = await request.json(); } catch { return json({ error: 'Bad request' }, 400); }
  const username = (body.username || '').trim();
  const password = body.password || '';
  if (!username || !password) return json({ error: 'Missing username or password' }, 400);

  // First-run bootstrap: if there are no users yet, seed the admin from env secrets.
  try {
    const countRow = await DB.prepare('SELECT COUNT(*) AS n FROM users').first();
    if (countRow && countRow.n === 0 && BOOTSTRAP_USER && BOOTSTRAP_PASS) {
      const hash = await hashPassword(BOOTSTRAP_PASS);
      await DB.prepare(
        'INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)'
      ).bind(BOOTSTRAP_USER, hash, 'admin', Date.now()).run();
    }
  } catch (e) {
    return json({ error: 'Database not initialized. Run schema.sql (see SETUP-PORTAL.md).' }, 503);
  }

  const user = await DB.prepare('SELECT username, password, role FROM users WHERE username = ?')
    .bind(username).first();

  if (!user || !(await verifyPassword(password, user.password))) {
    return json({ error: 'Invalid username or password' }, 401);
  }

  const token = await createToken(SESSION_SECRET, { u: user.username, r: user.role });
  return json(
    { ok: true, user: { username: user.username, role: user.role } },
    200,
    { 'Set-Cookie': sessionCookie(token) }
  );
}
