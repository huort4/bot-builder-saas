CREATE TABLE IF NOT EXISTS stores (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER NOT NULL,
  store_name TEXT NOT NULL,
  category TEXT,
  card_number TEXT,
  accept_stars INTEGER NOT NULL DEFAULT 1,
  channel_id TEXT NOT NULL UNIQUE,
  bot_token TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
