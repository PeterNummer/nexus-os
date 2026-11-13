
const SESSION_DAYS = 30;
const PASSWORD_ITERATIONS = 310000;

function json(data, status = 200, headers = {}) {
  return Response.json(data, { status, headers });
}

function randomHex(bytes = 32) {
  const array = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(array, b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(value) {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return Array.from(new Uint8Array(hash), b =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt),
      iterations: PASSWORD_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return Array.from(new Uint8Array(bits), b =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  const entry = cookies.split(";").map(v => v.trim())
    .find(v => v.startsWith(name + "="));

  return entry ? entry.slice(name.length + 1) : null;
}

function sessionCookie(token) {
  return `nexus_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}`;
}

function clearSessionCookie() {
  return "nexus_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
}

async function getUser(request, env) {
  const token = getCookie(request, "nexus_session");
  if (!token) return null;

  const tokenHash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);

  const result = await env.DB.prepare(`
    SELECT users.id, users.username
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
      AND sessions.expires_at > ?
  `).bind(tokenHash, now).first();

  return result || null;
}

async function createSession(userId, env) {
  const token = randomHex(32);
  const tokenHash = await sha256(token);
  const expiresAt = Math.floor(Date.now() / 1000)
    + SESSION_DAYS * 86400;

  await env.DB.prepare(`
    INSERT INTO sessions (token_hash, user_id, expires_at)
    VALUES (?, ?, ?)
  `).bind(tokenHash, userId, expiresAt).run();

  return token;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // REGISTRIERUNG
      if (path === "/api/auth/register" && request.method === "POST") {
        const data = await request.json();
        const username = String(data.username || "").trim();
        const password = String(data.password || "");

        if (!/^[a-zA-Z0-9_-]{3,20}$/.test(username)) {
          return json({
            error: "Der Benutzername muss 3–20 Zeichen lang sein und darf nur Buchstaben, Zahlen, _ und - enthalten."
          }, 400);
        }

        if (password.length < 8 || password.length > 128) {
          return json({
            error: "Das Passwort muss mindestens 8 und höchstens 128 Zeichen lang sein."
          }, 400);
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM users WHERE username = ?"
        ).bind(username).first();

        if (existing) {
          return json({ error: "Dieser Benutzername ist bereits vergeben." }, 409);
        }

        const userId = crypto.randomUUID();
        const salt = randomHex(16);
        const passwordHash = await hashPassword(password, salt);

        await env.DB.prepare(`
          INSERT INTO users (id, username, password_hash, password_salt)
          VALUES (?, ?, ?, ?)
        `).bind(userId, username, passwordHash, salt).run();

        // Alte Einstellungen dem ersten registrierten Konto zuordnen.
        const count = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM users"
        ).first();

        if (count.total === 1) {
          await env.DB.prepare(`
            INSERT INTO user_settings (user_id, key, value)
            SELECT ?, key, value FROM settings
            ON CONFLICT(user_id, key)
            DO NOTHING
          `).bind(userId).run();
        }

        const token = await createSession(userId, env);

        return json(
          { success: true, username },
          201,
          { "Set-Cookie": sessionCookie(token) }
        );
      }

      // LOGIN
      if (path === "/api/auth/login" && request.method === "POST") {
        const data = await request.json();
        const username = String(data.username || "").trim();
        const password = String(data.password || "");

        const user = await env.DB.prepare(`
          SELECT id, username, password_hash, password_salt
          FROM users
          WHERE username = ?
        `).bind(username).first();

        if (!user) {
          return json({ error: "Benutzername oder Passwort falsch." }, 401);
        }

        const passwordHash = await hashPassword(password, user.password_salt);

        if (passwordHash !== user.password_hash) {
          return json({ error: "Benutzername oder Passwort falsch." }, 401);
        }

        const token = await createSession(user.id, env);

        return json(
          { success: true, username: user.username },
          200,
          { "Set-Cookie": sessionCookie(token) }
        );
      }

      // AKTUELLEN LOGIN PRÜFEN
      if (path === "/api/auth/me" && request.method === "GET") {
        const user = await getUser(request, env);

        if (!user) {
          return json({ authenticated: false });
        }

        return json({
          authenticated: true,
          username: user.username
        });
      }

      // LOGOUT
      if (path === "/api/auth/logout" && request.method === "POST") {
        const token = getCookie(request, "nexus_session");

        if (token) {
          await env.DB.prepare(
            "DELETE FROM sessions WHERE token_hash = ?"
          ).bind(await sha256(token)).run();
        }

        return json(
          { success: true },
          200,
          { "Set-Cookie": clearSessionCookie() }
        );
      }

      // BENUTZER-EINSTELLUNGEN LADEN
      if (path === "/api/data" && request.method === "GET") {
        const user = await getUser(request, env);

        if (!user) {
          return json({ error: "Nicht angemeldet." }, 401);
        }

        const result = await env.DB.prepare(`
          SELECT key, value
          FROM user_settings
          WHERE user_id = ?
        `).bind(user.id).all();

        return json(result.results);
      }

      // BENUTZER-EINSTELLUNGEN SPEICHERN
      if (path === "/api/data" && request.method === "POST") {
        const user = await getUser(request, env);

        if (!user) {
          return json({ error: "Nicht angemeldet." }, 401);
        }

        const data = await request.json();

        if (
          typeof data.key !== "string" ||
          data.key.length < 1 ||
          data.key.length > 100 ||
          data.value === undefined
        ) {
          return json({ error: "Ungültige Daten." }, 400);
        }

        await env.DB.prepare(`
          INSERT INTO user_settings (user_id, key, value)
          VALUES (?, ?, ?)
          ON CONFLICT(user_id, key)
          DO UPDATE SET
            value = excluded.value,
            updated_at = CURRENT_TIMESTAMP
        `).bind(user.id, data.key, JSON.stringify(data.value)).run();

        return json({ success: true });
      }

      // ALLE ANDEREN ANFRAGEN AN DIE WEBSITE
      return env.ASSETS.fetch(request);

    } catch (error) {
      console.error("NEXUS API error:", error);
      return json({ error: "Interner Serverfehler." }, 500);
    }
  }
};
