-- GreenPath Horizons instructor portal — D1 schema
CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  username   TEXT UNIQUE NOT NULL,
  password   TEXT NOT NULL,          -- pbkdf2$iterations$saltB64$hashB64
  role       TEXT NOT NULL DEFAULT 'instructor',  -- 'admin' | 'instructor'
  created_at INTEGER NOT NULL
);
