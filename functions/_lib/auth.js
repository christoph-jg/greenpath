// Shared auth helpers for GreenPath Horizons instructor portal.
// Runs on the Cloudflare Workers runtime (Web Crypto available as globalThis.crypto).
// Files in _lib are NOT routed (underscore-prefixed) but can be imported.

const te = new TextEncoder();

function b64(bytes) { return btoa(String.fromCharCode(...bytes)); }
function unb64(str) { return Uint8Array.from(atob(str), c => c.charCodeAt(0)); }
function b64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64url(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, 256
  );
  return new Uint8Array(bits);
}

// Stored format: pbkdf2$<iterations>$<saltB64>$<hashB64>
export async function hashPassword(password) {
  const iterations = 100000;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, iterations);
  return `pbkdf2$${iterations}$${b64(salt)}$${b64(hash)}`;
}

export async function verifyPassword(password, stored) {
  try {
    const [scheme, iterStr, saltB64, hashB64] = String(stored).split('$');
    if (scheme !== 'pbkdf2') return false;
    const salt = unb64(saltB64);
    const expected = unb64(hashB64);
    const actual = await pbkdf2(password, salt, parseInt(iterStr, 10));
    if (actual.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
    return diff === 0;
  } catch {
    return false;
  }
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, te.encode(data));
  return new Uint8Array(sig);
}

// Stateless signed token: base64url(payload).base64url(hmac)
export async function createToken(secret, payload, ttlSeconds = 60 * 60 * 12) {
  const body = { ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds };
  const p = b64url(te.encode(JSON.stringify(body)));
  const sig = b64url(await hmac(secret, p));
  return `${p}.${sig}`;
}

export async function verifyToken(secret, token) {
  if (!secret || !token || token.indexOf('.') === -1) return null;
  const [p, sig] = token.split('.');
  const expected = b64url(await hmac(secret, p));
  // constant-time-ish compare of equal-length base64url strings
  if (sig.length !== expected.length) return null;
  let diff = 0;
  for (let i = 0; i < sig.length; i++) diff |= sig.charCodeAt(i) ^ expected.charCodeAt(i);
  if (diff !== 0) return null;
  try {
    const body = JSON.parse(new TextDecoder().decode(unb64url(p)));
    if (!body.exp || body.exp < Math.floor(Date.now() / 1000)) return null;
    return body;
  } catch {
    return null;
  }
}

export function getCookie(request, name) {
  const header = request.headers.get('Cookie') || '';
  const m = header.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : null;
}

const COOKIE = 'gp_session';
const MAXAGE = 60 * 60 * 12;
export function sessionCookie(token) {
  return `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${MAXAGE}`;
}
export function clearCookie() {
  return `${COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}
export const COOKIE_NAME = COOKIE;

// Returns the session payload ({u, r, exp}) or null.
export async function getSession(request, env) {
  return verifyToken(env.SESSION_SECRET, getCookie(request, COOKIE));
}
