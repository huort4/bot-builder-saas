export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  AI_API_KEY: string;
  TELEGRAM_BOT_TOKEN: string;
  WEBHOOK_SECRET: string; // اجباری
  CARD_ENC_KEY: string; // base64 از ۳۲ بایت تصادفی
  AI_MODEL?: string;
  UPSTASH_REDIS_REST_URL: string;
  UPSTASH_REDIS_REST_TOKEN: string;
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
// اتصال به Upstash Redis
// ==========================================
async function redis(env: Env, command: any[]): Promise<any> {
  if (!env.UPSTASH_REDIS_REST_URL || !env.UPSTASH_REDIS_REST_TOKEN) return null;
  
  try {
    const res = await fetch(env.UPSTASH_REDIS_REST_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.UPSTASH_REDIS_REST_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(command),
    });
    const data = (await res.json()) as { result?: any; error?: string };
    if (data.error) console.error("Upstash Error:", data.error);
    return data.result;
  } catch (e) {
    console.error("Upstash Fetch Error:", e);
    return null;
  }
}

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

  const adminId = await verifyInitData(String(body.init_data ?? ""), env.TELEGRAM_BOT_TOKEN);
  if (adminId === null) return json({ error: "invalid_init_data" }, 401);

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
// ایستگاه اول: داشبورد اصلی بات‌ساز (برای ادمین‌ها) + جستجو
// ==========================================
async function handleUserMessage(message: any, env: Env) {
  const chatId = message.chat.id;
  const text = String(message.text || "").trim();

  if (text === "/start") {
    const welcomeText = 
      "به پلتفرم بات‌ساز فروشگاهی (Nexus) خوش آمدید! 🚀\n\n" +
      "با استفاده از این سیستم می‌توانید در کمتر از یک دقیقه، کانال خود را به یک فروشگاه هوشمند تبدیل کنید. بدون نیاز به یک خط کدنویسی!";

    const keyboard = {
      inline_keyboard: [
        [
          { 
            text: "🏪 ساخت فروشگاه جدید", 
            web_app: { url: "https://bot-builder-saas.maryoa0001.workers.dev/" } 
          }
        ],
        [
          { text: "📊 مدیریت فروشگاه‌های من", callback_data: "manage_stores" }
        ],
        [
          { text: "💳 تسویه حساب و کیف پول", callback_data: "wallet" },
          { text: "📚 راهنمای اتصال", callback_data: "help" }
        ]
      ],
    };

    await tg(env, "sendMessage", { chat_id: chatId, text: welcomeText, reply_markup: keyboard });
    return; // خروج از تابع تا پیام /start به عنوان جستجو پردازش نشود
  }

  // بررسی وضعیت (State) جستجو از Redis
  if (env.UPSTASH_REDIS_REST_URL && env.UPSTASH_REDIS_REST_TOKEN) {
    const userState = await redis(env, ["GET", `state:${chatId}`]);

    if (userState === "awaiting_search") {
      // بلافاصله وضعیت را پاک می‌کنیم تا پیام‌های بعدی جستجو نشوند
      await redis(env, ["DEL", `state:${chatId}`]);

      const waitMsg = await tg(env, "sendMessage", { chat_id: chatId, text: "در حال جستجو... ⏳" });

      // جستجو در D1
      const results: any = await env.DB.prepare(
        `SELECT name, price_irr, is_on_sale, category 
         FROM products 
         WHERE name LIKE ? LIMIT 5`
      )
        .bind(`%${text}%`)
        .all();

      let reply = "";
      if (!results || !results.results || results.results.length === 0) {
        reply = `متأسفانه محصولی با نام "${text}" پیدا نشد. 😔`;
      } else {
        reply = `نتایج جستجو برای "${text}":\n\n`;
        results.results.forEach((p: any, i: number) => {
          const price = p.price_irr ? `${p.price_irr.toLocaleString("en-US")} تومان` : "قیمت توافقی/استارز";
          reply += `${i + 1}. 📦 ${p.name}\n💰 ${price}\n${p.is_on_sale ? "🔥 تخفیف ویژه\n" : ""}\n`;
        });
      }

      if (waitMsg.ok && waitMsg.result) {
        await tg(env, "editMessageText", {
          chat_id: chatId,
          message_id: waitMsg.result.message_id,
          text: reply,
        });
      } else {
        await tg(env, "sendMessage", { chat_id: chatId, text: reply });
      }
    }
  }
}

// ==========================================
// ایستگاه دوم: پردازش کلیک روی دکمه‌های داشبورد
// ==========================================
async function handleCallbackQuery(query: any, env: Env) {
  const data = query.data;
  const chatId = query.message?.chat?.id;
  if (!chatId) return;

  await tg(env, "answerCallbackQuery", { callback_query_id: query.id });

  let responseText = "";

  if (data === "manage_stores") {
    // گرفتن لیست فروشگاه‌های این ادمین از D1
    const stores: any = await env.DB.prepare(
      "SELECT store_name, channel_id, accept_stars FROM stores WHERE admin_id = ?"
    )
      .bind(chatId)
      .all();

    if (!stores || !stores.results || stores.results.length === 0) {
      responseText = "شما هنوز هیچ فروشگاهی نساخته‌اید! از دکمه «ساخت فروشگاه جدید» استفاده کنید. 🏪";
    } else {
      responseText = "لیست فروشگاه‌های فعال شما:\n\n";
      stores.results.forEach((s: any, i: number) => {
        responseText += `${i + 1}. 🛍 ${s.store_name}\n   کانال: ${s.channel_id}\n   وضعیت استارز: ${s.accept_stars ? "✅" : "❌"}\n\n`;
      });
      responseText += "برای افزودن محصول، کافیست ربات را در کانال خود ادمین کرده و پست بگذارید.";
    }
  } else if (data === "wallet") {
    responseText = "بخش مالی و تسویه حساب به زودی فعال می‌شود. 💳";
  } else if (data === "help") {
    responseText = "ابتدا از طریق مینی‌اپ فروشگاه خود را بسازید.\nسپس این ربات را در کانال خود ادمین کنید.\nهر پستی که در کانال بگذارید، به صورت خودکار به عنوان محصول در دیتابیس ثبت می‌شود!";
  } else if (data === "search") {
    // دکمه جستجو برای تست و تطابق کدهای قبلی (در داشبورد ادمین فعلاً قرار داده نشده ولی هندل می‌شود)
    if (env.UPSTASH_REDIS_REST_URL && env.UPSTASH_REDIS_REST_TOKEN) {
      await redis(env, ["SET", `state:${chatId}`, "awaiting_search", "EX", 300]);
    }
    responseText = "نام محصول مورد نظر را تایپ کنید: 🔍";
  } else {
    responseText = "این بخش در حال توسعه است! 🚧";
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

  const store: any = await env.DB.prepare(
    `SELECT id, channel_chat_id FROM stores
     WHERE channel_chat_id = ? OR channel_id = ? OR channel_id = ?
     ORDER BY (channel_chat_id = ?) DESC
     LIMIT 1`
  )
    .bind(chatId, chatId, username, chatId)
    .first();
  if (!store) return;

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
