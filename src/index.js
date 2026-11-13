
export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    if (url.pathname === "/api/data" && request.method === "GET") {
      const result = await env.DB.prepare(
        "SELECT key, value FROM settings"
      ).all();

      return Response.json(result.results, {
        headers: corsHeaders
      });
    }

    if (url.pathname === "/api/data" && request.method === "POST") {
      const data = await request.json();

      await env.DB.prepare(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
      ).bind(data.key, JSON.stringify(data.value)).run();

      return Response.json({ success: true }, {
        headers: corsHeaders
      });
    }

    return new Response("NEXUS OS API online", {
      headers: corsHeaders
    });
  }
};
