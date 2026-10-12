export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  AI_API_KEY: string;
  TELEGRAM_BOT_TOKEN: string;
  WEBHOOK_SECRET: string; // اجباری
  CARD_ENC_KEY: string; // base64 از ۳۲ بایت تصادفی
  AI_MODEL?: string;
}

const ALLOWED_CATEGORIES = ["فایل و دیجیتال", "پوشاک", "خدمات", "کانفیگ و اکانت"];

const HTML_SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://telegram.org; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors https://web.telegram.org https://*.telegram.org",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // API مینی‌اپ (هم‌مبدأ با صفحه؛ CORS لازم نیست)
    if (url.pathname === "/api/stores" && request.method === "POST") {
      return handleCreateStore(request, env);
    }

    // صفحه‌ی مینی‌اپ از پوشه public (فقط GET/HEAD)
    if (request.method === "GET" || request.method === "HEAD") {
      const res = await env.ASSETS.fetch(request);
      if ((res.headers.get("Content-Type") ?? "").includes("text/html")) {
        const headers = new Headers(res.headers);
        for (const [k, v] of Object.entries(HTML_SECURITY_HEADERS)) headers.set(k, v);
        return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
      }
      return res;
    }

    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    // ---- وب‌هوک تلگرام ----
    if (!env.WEBHOOK_SECRET) return new Response("Server misconfigured", { status: 500 });
    if (request.headers.get("X-Telegram-Bot-Api-Secret-Token") !== env.WEBHOOK_SECRET) {
      return new Response("Forbidden", { status: 403 });
    }

    try {
      const update = (await request.json()) as {
        channel_post?: any;
        edited_channel_post?: any;
        message?: any;
        callback_query?: any;
      };

      const channelPost = update.channel_post ?? update.edited_channel_post;
      if (channelPost) {
        ctx.waitUntil(handleChannelPost(channelPost, env).catch(console.error));
      } else if (update.message) {
        ctx.waitUntil(handleUserMessage(update.message, env).catch(console.error));
      } else if (update.callback_query) {
        ctx.waitUntil(handleCallbackQuery(update.callback_query, env).catch(console.error));
      }
    } catch (error) {
      console.error(error);
    }
    // همیشه OK تا تلگرام درخواست را بی‌نهایت تکرار نکند
    return new Response("OK", { status: 200 });
  },
};

// ==========================================
// ارسال درخواست به API تلگرام
// ==========================================
async function tg(env: Env, method: string, payload: unknown) {
  try {
    const res = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = (await res.json()) as { ok: boolean; result?: any; description?: string };
    if (!data.ok) console.error(`Telegram ${method} failed:`, res.status, data.description);
    return data;
  } catch (e) {
    console.error(`Telegram ${method} error:`, e);
    return { ok: false as const, result: undefined, description: "network_error" };
  }
}

// ==========================================
// ابزارهای کمکی
// ==========================================

// تبدیل ارقام فارسی و عربی به لاتین
function normalizeDigits(input: string): string {
  return input
    .replace(/[۰-۹]/g, (d) => String(d.charCodeAt(0) - 0x06f0))
    .replace(/[٠-٩]/g, (d) => String(d.charCodeAt(0) - 0x0660));
}

function luhn(num: string): boolean {
  let sum = 0;
  for (let i = 0; i < num.length; i++) {
    let d = Number(num[num.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

function hex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256(key: ArrayBuffer | string, data: string): Promise<ArrayBuffer> {
  const raw = typeof key === "string" ? new TextEncoder().encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    raw,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(data));
}

// اعتبارسنجی initData مینی‌اپ تلگرام؛ در صورت معتبر بودن، شناسه کاربر را برمی‌گرداند
async function verifyInitData(
  initData: string,
  botToken: string,
  maxAgeSeconds = 24 * 60 * 60
): Promise<number | null> {
  if (!initData || initData.length > 4096) return null;

  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash) return null;
  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

  const secretKey = await hmacSha256("WebAppData", botToken);
  const expected = hex(await hmacSha256(secretKey, dataCheckString));

  // مقایسه هم‌زمان‌ثابت
  if (expected.length !== hash.length) return null;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ hash.charCodeAt(i);
  if (diff !== 0) return null;

  const authDate = Number(params.get("auth_date"));
  if (!Number.isFinite(authDate) || Date.now() / 1000 - authDate > maxAgeSeconds) return null;

  try {
    const user = JSON.parse(params.get("user") ?? "");
    const id = Number(user?.id);
    return Number.isInteger(id) && id > 0 ? id : null;
  } catch {
    return null;
  }
}

// رمزنگاری AES-GCM؛ خروجی: base64(iv[12] + ciphertext)
async function encryptCard(plain: string, keyB64: string): Promise<string> {
  const raw = Uint8Array.from(atob(keyB64), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plain))
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  let bin = "";
  out.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}

// ==========================================
// ثبت فروشگاه از مینی‌اپ تلگرام
// ==========================================
async function handleCreateStore(request: Request, env: Env): Promise<Response> {
  if (!env.TELEGRAM_BOT_TOKEN) return json({ error: "server_misconfigured" }, 500);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  // ۱) هویت ادمین فقط از initData امضاشده تلگرام گرفته می‌شود
  const adminId = await verifyInitData(String(body.init_data ?? ""), env.TELEGRAM_BOT_TOKEN);
  if (adminId === null) return json({ error: "invalid_init_data" }, 401);

  // ۲) اعتبارسنجی ورودی‌ها
  const storeName = String(body.store_name ?? "").trim();
  const category = String(body.category ?? "").trim();
  const cardNumber = normalizeDigits(String(body.card_number ?? ""))
    .replace(/[\s-]/g, "")
    .toUpperCase();
  const acceptStars = body.accept_stars ? 1 : 0;
  let channelId = normalizeDigits(String(body.channel_id ?? "")).trim();

  if (!storeName || storeName.length > 64) return json({ error: "invalid_store_name" }, 400);
  if (!ALLOWED_CATEGORIES.includes(category)) return json({ error: "invalid_category" }, 400);
  if (!/^@[A-Za-z][A-Za-z0-9_]{4,31}$/.test(channelId) && !/^-100\d+$/.test(channelId)) {
    return json({ error: "invalid_channel_id" }, 400);
  }
  if (cardNumber) {
    const okFormat = /^(\d{16}|IR\d{24})$/.test(cardNumber);
    if (!okFormat || (/^\d{16}$/.test(cardNumber) && !luhn(cardNumber))) {
      return json({ error: "invalid_card_number" }, 400);
    }
    if (!env.CARD_ENC_KEY) return json({ error: "server_misconfigured" }, 500);
  }
  if (channelId.startsWith("@")) channelId = channelId.toLowerCase();

  // ۳) بررسی مالکیت کانال: کانال باشد، ربات ادمین باشد، کاربر هم ادمین باشد
  const chat = await tg(env, "getChat", { chat_id: channelId });
  if (!chat.ok || chat.result?.type !== "channel") {
    return json({ error: "channel_not_found" }, 400);
  }
  const chatId = String(chat.result.id);
  const botId = Number(env.TELEGRAM_BOT_TOKEN.split(":")[0]);

  const [botMember, userMember] = await Promise.all([
    tg(env, "getChatMember", { chat_id: chatId, user_id: botId }),
    tg(env, "getChatMember", { chat_id: chatId, user_id: adminId }),
  ]);

  if (!botMember.ok || botMember.result?.status !== "administrator") {
    return json({ error: "bot_not_admin" }, 403);
  }
  if (!userMember.ok || !["creator", "administrator"].includes(userMember.result?.status)) {
    return json({ error: "not_channel_admin" }, 403);
  }

  // ۴) رمزنگاری کارت و ذخیره
  let cardEncrypted: string | null = null;
  try {
    cardEncrypted = cardNumber ? await encryptCard(cardNumber, env.CARD_ENC_KEY) : null;
  } catch (e) {
    console.error("encryptCard failed:", e);
    return json({ error: "server_misconfigured" }, 500);
  }
  const cardLast4 = cardNumber ? cardNumber.slice(-4) : null;

  try {
    await env.DB.prepare(
      `INSERT INTO stores
         (admin_id, store_name, category, card_encrypted, card_last4, accept_stars, channel_id, channel_chat_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(adminId, storeName, category, cardEncrypted, cardLast4, acceptStars, channelId, chatId)
      .run();
  } catch (e: any) {
    if (String(e?.message).includes("UNIQUE")) return json({ error: "channel_already_registered" }, 409);
    console.error(e);
    return json({ error: "db_error" }, 500);
  }
  return json({ ok: true });
}

// ==========================================
// ایستگاه اول: پیام‌های کاربر (منوی خوش‌آمدگویی)
// ==========================================
async function handleUserMessage(message: any, env: Env) {
  const chatId = message.chat.id;
  const text = message.text;

  if (text === "/start") {
    const welcomeText =
      "سلام رفیق! 👋\nبه فروشگاه هوشمند ما خوش اومدی. از منوی زیر می‌تونی محصولات رو ببینی یا سفارشت رو پیگیری کنی:";

    const keyboard = {
      inline_keyboard: [
        [
          { text: "🛍 دسته‌بندی محصولات", callback_data: "categories" },
          { text: "🔍 جستجوی هوشمند", callback_data: "search" },
        ],
        [
          { text: "🛒 سبد خرید من", callback_data: "cart" },
          { text: "📦 پیگیری سفارشات", callback_data: "track" },
        ],
        [
          { text: "🎧 پشتیبانی آنلاین", callback_data: "support" },
          { text: "ℹ️ درباره فروشگاه", callback_data: "about" },
        ],
      ],
    };

    await tg(env, "sendMessage", { chat_id: chatId, text: welcomeText, reply_markup: keyboard });
  }
}

// ==========================================
// ایستگاه دوم: پردازش کلیک روی دکمه‌های شیشه‌ای
// ==========================================
async function handleCallbackQuery(query: any, env: Env) {
  const data = query.data;
  const chatId = query.message?.chat?.id;
  if (!chatId) return;

  // خاموش کردن حالت لودینگ دکمه
  await tg(env, "answerCallbackQuery", { callback_query_id: query.id });

  let responseText = "";
  if (data === "categories") {
    responseText = "بخش دسته‌بندی‌ها در حال اتصال به پایگاه داده است... 🛍";
  } else if (data === "cart") {
    responseText = "سبد خرید شما در حال حاضر خالی است. 🛒";
  } else if (data === "search") {
    responseText = "نام محصول مورد نظر را تایپ کنید: 🔍";
  } else {
    responseText = "این بخش به زودی فعال می‌شود! 🚧";
  }

  await tg(env, "sendMessage", { chat_id: chatId, text: responseText });
}

// ==========================================
// پردازش پست‌های کانال (استخراج هوشمند + ویرایش پست)
// ==========================================
async function handleChannelPost(post: any, env: Env) {
  const text = post.text || post.caption;
  if (!text) return;

  const chatId = String(post.chat.id);
  const username = post.chat.username ? "@" + String(post.chat.username).toLowerCase() : "";

  // اولویت با آیدی عددی ثبت‌شده؛ برای فروشگاه‌های قدیمی (بدون channel_chat_id) با channel_id هم پیدا می‌شود
  const store: any = await env.DB.prepare(
    `SELECT id, channel_chat_id FROM stores
     WHERE channel_chat_id = ? OR channel_id = ? OR channel_id = ?
     ORDER BY (channel_chat_id = ?) DESC
     LIMIT 1`
  )
    .bind(chatId, chatId, username, chatId)
    .first();
  if (!store) return;

  // پر کردن آیدی عددی برای فروشگاه‌های قدیمی
  if (!store.channel_chat_id) {
    await env.DB.prepare("UPDATE stores SET channel_chat_id = ? WHERE id = ? AND channel_chat_id IS NULL")
      .bind(chatId, store.id)
      .run()
      .catch(console.error);
  }

  const product = await extractProductWithAI(text, env);
  if (!product) return;

  await env.DB.prepare(
    `INSERT INTO products
       (store_id, source_message_id, name, type, price_irr, price_stars, is_on_sale, category, cross_sell_tags, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
     ON CONFLICT(store_id, source_message_id) DO UPDATE SET
       name = excluded.name,
       type = excluded.type,
       price_irr = excluded.price_irr,
       price_stars = excluded.price_stars,
       is_on_sale = excluded.is_on_sale,
       category = excluded.category,
       cross_sell_tags = excluded.cross_sell_tags,
       updated_at = datetime('now')`
  )
    .bind(
      store.id,
      post.message_id,
      product.name,
      product.type,
      product.price_irr,
      product.price_stars,
      product.is_on_sale ? 1 : 0,
      product.category,
      JSON.stringify(product.cross_sell_tags)
    )
    .run();
}

interface Product {
  name: string;
  type: "physical" | "digital";
  price_irr: number | null;
  price_stars: number | null;
  is_on_sale: boolean;
  category: string | null;
  cross_sell_tags: string[];
}

async function extractProductWithAI(text: string, env: Env): Promise<Product | null> {
  const systemPrompt = `تو مغز متفکر یک پلتفرم فروشگاهی هستی. کپشن را بخوان و یک JSON معتبر برگردان.
اگر متن یک محصول برای فروش نیست (اطلاعیه، تبلیغ کانال، پیام عمومی و ...) فقط {"is_product": false} برگردان.
در غیر این صورت فیلدها: is_product (true), name, type ("physical" یا "digital"), price_irr (عدد یا null), price_stars (عدد یا null), is_on_sale (true/false), category, cross_sell_tags (آرایه 3 کلمه‌ای).
قیمت‌ها را فقط به صورت عدد انگلیسی و بدون جداکننده یا واحد بنویس.`;

  try {
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${env.AI_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: env.AI_MODEL || "llama-3.3-70b-versatile",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: text },
        ],
        response_format: { type: "json_object" },
        temperature: 0.1,
      }),
    });

    if (!response.ok) {
      console.error("AI API error:", response.status, await response.text());
      return null;
    }

    const data: any = await response.json();
    const raw = JSON.parse(data.choices[0].message.content);
    if (raw.is_product === false) return null;

    const name = String(raw.name ?? "").trim();
    if (!name) return null;

    const toPrice = (v: any) => {
      const n = Number(normalizeDigits(String(v ?? "")).replace(/[,٬\s]/g, ""));
      return Number.isFinite(n) && n > 0 ? Math.round(n) : null;
    };

    return {
      name: name.slice(0, 200),
      type: raw.type === "digital" ? "digital" : "physical",
      price_irr: toPrice(raw.price_irr),
      price_stars: toPrice(raw.price_stars),
      is_on_sale: raw.is_on_sale === true,
      category: raw.category ? String(raw.category).slice(0, 100) : null,
      cross_sell_tags: Array.isArray(raw.cross_sell_tags)
        ? raw.cross_sell_tags.slice(0, 5).map(String)
        : [],
    };
  } catch (e) {
    console.error("extractProductWithAI failed:", e);
    return null;
  }
}
