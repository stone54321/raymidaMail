/**
 * Email Worker for raymida.com - catches email and forwards to our receiver.
 * With R2 fallback: if local server is down, saves to R2 queue.
 *
 * Variables (Settings → Variables and Secrets):
 *   PRIYOMNIK = https://mail.raymida.com/inbound
 *   KEY       = Your secret key (INBOUND_KEY or RAY_MAIL_KEY)
 *
 * R2 Binding:
 *   MAIL_QUEUE → mail-fallback-queue
 *
 * Email Routing Rules: ray@raymida.com → Send to Worker.
 */
export default {
  async fetch(request, env, ctx) {
    // Health check endpoint
    const stroki = [];
    stroki.push("📮 Email Worker raymida.com (R2 Fallback)");
    stroki.push(`PRIYOMNIK = ${env.PRIYOMNIK || "❌ NOT SET"}`);
    stroki.push(`KEY = ${env.KEY ? `✓ ${env.KEY.length} chars` : "❌ NOT SET"}`);
    stroki.push(`R2 QUEUE = ${env.MAIL_QUEUE ? "✓ Bound" : "❌ Not bound"}`);

    if (env.PRIYOMNIK && env.KEY) {
      const healthUrl = env.PRIYOMNIK.replace(/\/(vhod|inbound)$/, "/health");
      try {
        const otvet = await fetch(healthUrl, { method: "GET" });
        stroki.push(`receiver ${healthUrl} → ${otvet.status} ${await otvet.text()}`);
      } catch (beda) {
        stroki.push(`receiver unavailable: ${beda}`);
      }
    }

    return new Response(stroki.join("\n") + "\n", {
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  },

  async email(message, env, ctx) {
    try {
      const raw = await new Response(message.raw).arrayBuffer();
      if (env.PRIYOMNIK && env.KEY) {
        try {
          const response = await fetch(env.PRIYOMNIK, {
            method: "POST",
            headers: {
              "Content-Type": "message/rfc822",
              "X-Webhook-Key": env.KEY,
              "X-Original-To": message.to,
              "X-Ray-To": message.to,
              "X-Ray-From": message.from,
            },
            body: raw,
            signal: AbortSignal.timeout(6000),
          });
          if (response.ok) return;
          console.warn(`Receiver rejected delivery: ${response.status}; using R2`);
        } catch (error) {
          console.warn("Receiver unavailable; using R2");
        }
      }
      await saveToR2(env, raw, message.to);
    } catch (error) {
      // Never acknowledge a message which is neither delivered nor stored.
      message.setReject("RAYMIDA could not store this email. Please retry later.");
      console.error("Email delivery and durable storage failed");
    }
  }

};

async function saveToR2(env, rawBuffer, to) {
  if (!env.MAIL_QUEUE) {
    throw new Error("R2 MAIL_QUEUE binding is missing; email was not accepted");
  }

  // Генерируем безопасное имя файла: pending/timestamp-random.eml
  const timestamp = Date.now();
  const randomStr = crypto.randomUUID();
  const filename = `pending/${timestamp}-${randomStr}.eml`;

  try {
    await env.MAIL_QUEUE.put(filename, rawBuffer, {
      httpMetadata: { contentType: "message/rfc822" },
      customMetadata: { originalTo: to }
    });
    console.log(`✅ Saved to R2: ${filename}`);
  } catch (error) {
    console.error(`❌ Failed to save to R2: ${error}`);
    throw error;
  }
}
