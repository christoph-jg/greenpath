import { getSession } from '../_lib/auth.js';

// Gate everything under /portal — redirect to /login if not signed in.
export async function onRequest(context) {
  const { request, env, next } = context;
  const session = await getSession(request, env);
  if (!session) {
    const url = new URL(request.url);
    const dest = '/login?next=' + encodeURIComponent(url.pathname + url.search);
    return new Response(null, { status: 302, headers: { Location: dest } });
  }
  return next();
}
