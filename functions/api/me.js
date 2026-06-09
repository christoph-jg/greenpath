import { getSession } from '../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const s = await getSession(request, env);
  if (!s) {
    return new Response(JSON.stringify({ error: 'unauthorized' }), {
      status: 401, headers: { 'Content-Type': 'application/json' },
    });
  }
  return new Response(JSON.stringify({ username: s.u, role: s.r }), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  });
}
