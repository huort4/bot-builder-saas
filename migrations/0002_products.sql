CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  store_id INTEGER NOT NULL REFERENCES stores(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'physical' CHECK (type IN ('physical', 'digital')),
  price_irr INTEGER,
  price_stars INTEGER,
  is_on_sale INTEGER NOT NULL DEFAULT 0,
  category TEXT,
  cross_sell_tags TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_products_store ON products(store_id);
