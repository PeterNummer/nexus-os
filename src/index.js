
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/data" && request.method === "GET") {
      const result = await env.DB.prepare(
        "SELECT key, value FROM settings"
      ).all();

      return Response.json(result.results);
    }

    if (url.pathname === "/api/data" && request.method === "POST") {
      const data = await request.json();

      if (!data.key || data.value === undefined) {
        return Response.json(
          { error: "Invalid data" },
          { status: 400 }
        );
      }

      await env.DB.prepare(`
        INSERT INTO settings (key, value)
        VALUES (?, ?)
        ON CONFLICT(key)
        DO UPDATE SET value = excluded.value
      `).bind(data.key, JSON.stringify(data.value)).run();

      return Response.json({ success: true });
    }

    return env.ASSETS.fetch(request);
  }
};
