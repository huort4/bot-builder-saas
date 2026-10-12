-- ارتقای امنیتی: رمزنگاری کارت، آیدی عددی کانال، جلوگیری از محصول تکراری
-- (wrangler فقط یک‌بار این فایل را اجرا می‌کند؛ ALTER TABLE ایمن است)

-- stores
ALTER TABLE stores ADD COLUMN card_encrypted TEXT;
ALTER TABLE stores ADD COLUMN card_last4 TEXT;
ALTER TABLE stores ADD COLUMN channel_chat_id TEXT;

-- در SQLite چند مقدار NULL در ایندکس یکتا مجاز است؛ فروشگاه‌های قدیمی
-- با اولین پست کانال، channel_chat_id‌شان خودکار پر می‌شود.
CREATE UNIQUE INDEX IF NOT EXISTS idx_stores_chat_id ON stores(channel_chat_id);
CREATE INDEX IF NOT EXISTS idx_stores_admin ON stores(admin_id);

-- چهار رقم آخر کارت‌های قدیمی (ستون card_number دست‌نخورده می‌ماند؛ پایین را ببینید)
UPDATE stores SET card_last4 = substr(card_number, -4)
WHERE card_number IS NOT NULL AND card_number <> '';

-- products
ALTER TABLE products ADD COLUMN source_message_id INTEGER;
ALTER TABLE products ADD COLUMN updated_at TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_products_source ON products(store_id, source_message_id);

-- بعد از اطمینان از دیپلوی، شماره کارت‌های متن ساده را پاک کنید (در یک مایگریشن جدا):
-- UPDATE stores SET card_number = NULL;
