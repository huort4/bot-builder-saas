export interface Env {
  DB: D1Database;
  AI_API_KEY: string;
  TELEGRAM_BOT_TOKEN: string;
  AI_MODEL?: string;
  WEBHOOK_SECRET?: string;
}

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    // API اپلیکیشن فلاتر
    if (url.pathname === "/api/stores" && request.method === "POST") {
      return handleCreateStore(request, env);
    }

    if (request.method !== "POST") {
      return new Response("Bot-Builder SaaS Webhook is Active! 🚀", { status: 200 });
    }

    // اگر WEBHOOK_SECRET تنظیم شده باشد، فقط درخواست‌های واقعی تلگرام پذیرفته می‌شوند
    if (
      env.WEBHOOK_SECRET &&
      request.headers.get("X-Telegram-Bot-Api-Secret-Token") !== env.WEBHOOK_SECRET
    ) {
      return new Response("Forbidden", { status: 403 });
    }

    try {
      const update = (await request.json()) as {
        channel_post?: any;
        message?: any;
        callback_query?: any;
      };

      // هدایت درخواست‌ها به بخش‌های مربوطه
      if (update.channel_post) {
        ctx.waitUntil(handleChannelPost(update.channel_post, env).catch(console.error));
      } else if (update.message) {
        ctx.waitUntil(handleUserMessage(update.message, env).catch(console.error));
      } else if (update.callback_query) {
        ctx.waitUntil(handleCallbackQuery(update.callback_query, env).catch(console.error));
      }

      return new Response("OK", { status: 200 });
    } catch (error) {
      console.error(error);
      return new Response("OK", { status: 200 });
    }
  },
};

// ==========================================
// ارسال درخواست به API تلگرام
// ==========================================
async function tg(env: Env, method: string, payload: unknown) {
  const res = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) console.error(`Telegram ${method} failed:`, res.status, await res.text());
}

// ==========================================
// ثبت فروشگاه از اپلیکیشن فلاتر
// ==========================================
async function handleCreateStore(request: Request, env: Env): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  const storeName = String(body.store_name ?? "").trim();
  const category = String(body.category ?? "").trim();
  const cardNumber = String(body.card_number ?? "").replace(/[\s-]/g, "");
  const acceptStars = body.accept_stars ? 1 : 0;
  const adminId = Number(body.admin_id);
  let channelId = String(body.channel_id ?? "").trim();

  if (!storeName || storeName.length > 64) return json({ error: "invalid_store_name" }, 400);
  if (!Number.isInteger(adminId) || adminId <= 0) return json({ error: "invalid_admin_id" }, 400);
  if (!/^@[A-Za-z][A-Za-z0-9_]{4,31}$/.test(channelId) && !/^-100\d+$/.test(channelId)) {
    return json({ error: "invalid_channel_id" }, 400);
  }
  if (cardNumber && !/^(\d{16}|IR\d{24})$/i.test(cardNumber)) {
    return json({ error: "invalid_card_number" }, 400);
  }
  if (channelId.startsWith("@")) channelId = channelId.toLowerCase();

  try {
    await env.DB.prepare(
      `INSERT INTO stores (admin_id, store_name, category, card_number, accept_stars, channel_id)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
      .bind(adminId, storeName, category, cardNumber || null, acceptStars, channelId)
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
// پردازش پست‌های کانال (استخراج هوشمند)
// ==========================================
async function handleChannelPost(post: any, env: Env) {
  const text = post.text || post.caption;
  if (!text) return;

  const channelId = post.chat.id.toString();
  const username = post.chat.username ? "@" + String(post.chat.username).toLowerCase() : "";

  // فروشگاه هم با آیدی عددی کانال پیدا می‌شود و هم با @username
  const store: any = await env.DB.prepare(
    "SELECT id FROM stores WHERE channel_id = ? OR channel_id = ?"
  )
    .bind(channelId, username)
    .first();
  if (!store) return;

  const product = await extractProductWithAI(text, env);
  if (!product) return;

  await env.DB.prepare(
    `INSERT INTO products (store_id, name, type, price_irr, price_stars, is_on_sale, category, cross_sell_tags)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      store.id,
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
فیلدها: name, type ("physical" یا "digital"), price_irr (عدد یا null), price_stars (عدد یا null), is_on_sale (true/false), category, cross_sell_tags (آرایه 3 کلمه‌ای).
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

    const name = String(raw.name ?? "").trim();
    if (!name) return null;

    const toPrice = (v: any) => {
      const n = Number(v);
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
