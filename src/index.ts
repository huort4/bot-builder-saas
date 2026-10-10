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
      // تعریف دقیق ساختار برای تایپ‌اسکریپت جهت رفع ارور
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

  // TODO: Call AI API to extract JSON
  // TODO: Insert JSON data into products table
}
