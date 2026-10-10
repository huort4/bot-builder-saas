export interface Env {
  DB: D1Database;
  AI_API_KEY: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (request.method !== "POST") {
      return new Response("Bot-Builder SaaS Webhook is Active! 🚀", { status: 200 });
    }
    
    try {
      const update = (await request.json()) as { channel_post?: any };
      
      if (update.channel_post) {
        ctx.waitUntil(handleChannelPost(update.channel_post, env));
      }
      return new Response("OK", { status: 200 });
    } catch (error) {
      return new Response("OK", { status: 200 });
    }
  }
};

async function handleChannelPost(post: any, env: Env) {
  const text = post.text || post.caption;
  const channelId = post.chat.id.toString();
  if (!text) return;

  const store: any = await env.DB.prepare(
    "SELECT bot_token FROM stores WHERE channel_id = ?"
  ).bind(channelId).first();
  if (!store) return;

  // استخراج اطلاعات با هوش مصنوعی
  const productData = await extractProductWithAI(text, env.AI_API_KEY);
  if (!productData) return;

  // ذخیره در دیتابیس D1
  await env.DB.prepare(
    `INSERT INTO products (store_bot_token, name, type, price_irr, price_stars, is_on_sale, category, cross_sell_tags) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    store.bot_token,
    productData.name,
    productData.type,
    productData.price_irr,
    productData.price_stars,
    productData.is_on_sale ? 1 : 0,
    productData.category,
    JSON.stringify(productData.cross_sell_tags)
  ).run();
}

async function extractProductWithAI(text: string, apiKey: string) {
  const systemPrompt = `تو مغز متفکر یک پلتفرم فروشگاهی هستی. کپشن را بخوان و یک JSON معتبر برگردان.
فیلدها: name, type ("physical" یا "digital"), price_irr (عدد یا null), price_stars (عدد یا null), is_on_sale (true/false), category, cross_sell_tags (آرایه 3 کلمه‌ای).`;

  try {
    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "llama3-70b-8192",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: text }
        ],
        response_format: { type: "json_object" },
        temperature: 0.1
      })
    });

    const data: any = await response.json();
    return JSON.parse(data.choices[0].message.content);
  } catch (e) {
    console.error("AI Extraction Error:", e);
    return null;
  }
                                 }
