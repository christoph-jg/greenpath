# Portal setup (Cloudflare)

The portal code deploys automatically with the site, but it stays **inert until you
finish these one-time steps** in the Cloudflare dashboard. Until then, `/login` just
says "Portal is not configured yet" and `/portal` redirects to `/login`. Nothing
sensitive is exposed.

Everything below is on Cloudflare's **free** tier.

---

## 1. Create the database (D1)

Dashboard → **Workers & Pages → D1 → Create database**
- Name: `greenpath-portal`

Then open the new database → **Console** tab → paste the contents of
[`schema.sql`](schema.sql) and run it. (This creates the `users` table.)

## 2. Bind the database to the site

Dashboard → **Workers & Pages → your Pages project (greenpath) → Settings → Functions
→ D1 database bindings → Add binding**
- Variable name: `DB`   ← must be exactly this
- D1 database: `greenpath-portal`

Add it for **Production** (and Preview if you use it).

## 3. Set the environment variables

Dashboard → **your Pages project → Settings → Environment variables → Production**.
Add these three (use the **Encrypt** option so they're stored as secrets):

| Name             | Value                                            |
|------------------|--------------------------------------------------|
| `SESSION_SECRET` | a long random string — generate one (see below)  |
| `BOOTSTRAP_USER` | `greenpath_admin`                                |
| `BOOTSTRAP_PASS` | the admin password you chose                      |

Generate a strong `SESSION_SECRET` on your Mac:
```
openssl rand -base64 48
```

## 4. Redeploy

Push any commit (or hit **Retry deployment** in the dashboard) so the new binding and
variables take effect.

## 5. First sign-in

Go to `https://<your-site>/login` and sign in with `greenpath_admin` + your password.
The **first** successful login auto-creates the admin account in the database from the
bootstrap variables.

After that works, you can (optionally) delete `BOOTSTRAP_USER` and `BOOTSTRAP_PASS` —
the admin now lives in the database. Leave `SESSION_SECRET` in place permanently
(changing it logs everyone out).

---

## Adding your Notion links

Edit [`portal/index.html`](portal/index.html) — near the top of the `<script>` there's
a `NOTION = { ... }` block. Paste your Notion share links there and push. Until then the
tiles show an "Add Notion link" badge.

## Adding more logins

Sign in as an admin → **Manage team accounts** → create usernames/passwords. New people
sign in at `/login`. You can make others admins too.

## Later: Keycloak

When you stand up Keycloak, we replace the credential check in
`functions/api/login.js` with an OIDC redirect to Keycloak. The session cookie,
the `/portal` gate (`functions/portal/_middleware.js`), and the dashboard all stay the
same — this isn't throwaway work.

## Notes / current limits

- Passwords are stored as PBKDF2-SHA256 hashes (100k iterations, per-user salt) — never plaintext, never in the repo.
- There's no self-service "change my password" yet. To rotate the admin password for now: create a second admin, sign in as them, remove the first admin, recreate it. (A change-password screen is an easy future add.)
- Sessions last 12 hours.
