
const SESSION_DAYS = 30;
const SESSION_COOKIE = "nexus_session";
const PBKDF2_ITERATIONS = 100000;

const encoder = new TextEncoder();

function json(data, status = 200, extraHeaders = {}) {
  return Response.json(data, {
    status,
    headers: extraHeaders
  });
}

function randomHex(length = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
}

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  return new Uint8Array(
    hex.match(/.{2}/g).map(byte => parseInt(byte, 16))
  );
}

async function sha256(value) {
  const result = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );
  return bytesToHex(result);
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const result = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: hexToBytes(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return bytesToHex(result);
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;

  let difference = 0;

  for (let i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return difference === 0;
}

function getCookie(request) {
  const cookies = request.headers.get("Cookie") || "";

  const entry = cookies
    .split(";")
    .map(value => value.trim())
    .find(value => value.startsWith(SESSION_COOKIE + "="));

  return entry ? entry.substring(SESSION_COOKIE.length + 1) : null;
}

function sessionCookie(token, maxAge = SESSION_DAYS * 86400) {
  return `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

async function createSession(env, userId) {
  const token = randomHex(32);
  const tokenHash = await sha256(token);
  const expiresAt = Math.floor(Date.now() / 1000) +
    SESSION_DAYS * 86400;

  await env.DB.prepare(`
    INSERT INTO sessions (token_hash, user_id, expires_at)
    VALUES (?, ?, ?)
  `).bind(tokenHash, userId, expiresAt).run();

  return token;
}

async function getUser(request, env) {
  const token = getCookie(request);

  if (!token || !/^[a-f0-9]{64}$/i.test(token)) {
    return null;
  }

  const tokenHash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);

  return await env.DB.prepare(`
    SELECT users.id, users.username
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
      AND sessions.expires_at > ?
  `).bind(tokenHash, now).first();
}

async function handleRegister(request, env) {
  const data = await request.json();

  const username = String(data.username || "").trim();
  const password = String(data.password || "");

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return json({
      error: "Benutzername: 3–20 Zeichen, nur Buchstaben, Zahlen und _."
    }, 400);
  }

  if (password.length < 10 || password.length > 128) {
    return json({
      error: "Das Passwort muss 10 bis 128 Zeichen lang sein."
    }, 400);
  }

  const id = randomHex(16);
  const salt = randomHex(16);
  const passwordHash = await hashPassword(password, salt);

  try {
    await env.DB.prepare(`
      INSERT INTO users (id, username, password_hash, password_salt)
      VALUES (?, ?, ?, ?)
    `).bind(id, username, passwordHash, salt).run();
  } catch {
    return json({
      error: "Dieser Benutzername ist bereits vergeben."
    }, 409);
  }

  // Alte globale Einstellungen für den ersten Benutzer übernehmen.
  const count = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM users"
  ).first();

  if (Number(count.total) === 1) {
    const oldSettings = await env.DB.prepare(
      "SELECT key, value FROM settings"
    ).all();

    for (const setting of oldSettings.results) {
      await env.DB.prepare(`
        INSERT INTO user_settings (user_id, key, value)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, key)
        DO UPDATE SET value = excluded.value
      `).bind(id, setting.key, setting.value).run();
    }
  }

  const token = await createSession(env, id);

  return json({
    success: true,
    user: { id, username }
  }, 201, {
    "Set-Cookie": sessionCookie(token)
  });
}

async function handleLogin(request, env) {
  const data = await request.json();

  const username = String(data.username || "").trim();
  const password = String(data.password || "");

  if (!username || !password || password.length > 128) {
    return json({ error: "Ungültige Anmeldedaten." }, 400);
  }

  const user = await env.DB.prepare(`
    SELECT id, username, password_hash, password_salt
    FROM users
    WHERE username = ? COLLATE NOCASE
  `).bind(username).first();

  if (!user) {
    return json({ error: "Benutzername oder Passwort falsch." }, 401);
  }

  const passwordHash = await hashPassword(
    password,
    user.password_salt
  );

  if (!constantTimeEqual(passwordHash, user.password_hash)) {
    return json({ error: "Benutzername oder Passwort falsch." }, 401);
  }

  const token = await createSession(env, user.id);

  return json({
    success: true,
    user: {
      id: user.id,
      username: user.username
    }
  }, 200, {
    "Set-Cookie": sessionCookie(token)
  });
}

async function handleLogout(request, env) {
  const token = getCookie(request);

  if (token && /^[a-f0-9]{64}$/i.test(token)) {
    const tokenHash = await sha256(token);

    await env.DB.prepare(
      "DELETE FROM sessions WHERE token_hash = ?"
    ).bind(tokenHash).run();
  }

  return json({ success: true }, 200, {
    "Set-Cookie": sessionCookie("", 0)
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path.startsWith("/api/")) {
      if (!env.DB) {
        return json({ error: "Datenbank nicht verbunden." }, 500);
      }

      if (request.method === "POST") {
        if (request.headers.get("Origin") !== url.origin) {
          return json({ error: "Ungültige Anfrage." }, 403);
        }

        if (
          !(request.headers.get("Content-Type") || "")
            .toLowerCase()
            .includes("application/json")
        ) {
          return json({ error: "JSON erforderlich." }, 415);
        }

        const length = Number(
          request.headers.get("Content-Length") || 0
        );

        if (length > 16000) {
          return json({ error: "Anfrage zu groß." }, 413);
        }
      }

      try {
        if (path === "/api/auth/register" && request.method === "POST") {
          return await handleRegister(request, env);
        }

        if (path === "/api/auth/login" && request.method === "POST") {
          return await handleLogin(request, env);
        }

        if (path === "/api/auth/logout" && request.method === "POST") {
          return await handleLogout(request, env);
        }

        if (path === "/api/auth/me" && request.method === "GET") {
          const user = await getUser(request, env);

          if (!user) {
            return json({ user: null });
          }

          return json({
            user: {
              id: user.id,
              username: user.username
            }
          });
        }

        if (path === "/api/data" && request.method === "GET") {
          const user = await getUser(request, env);

          if (!user) {
            return json({ error: "Bitte anmelden." }, 401);
          }

          const result = await env.DB.prepare(`
            SELECT key, value
            FROM user_settings
            WHERE user_id = ?
          `).bind(user.id).all();

          const settings = result.results.map(item => {
            let value = item.value;

            try {
              value = JSON.parse(value);
            } catch {}

            return { key: item.key, value };
          });

          return json(settings);
        }

        if (path === "/api/data" && request.method === "POST") {
          const user = await getUser(request, env);

          if (!user) {
            return json({ error: "Bitte anmelden." }, 401);
          }

          const data = await request.json();

          if (
            typeof data.key !== "string" ||
            !/^[a-zA-Z0-9_.-]{1,80}$/.test(data.key) ||
            data.value === undefined
          ) {
            return json({ error: "Ungültige Daten." }, 400);
          }

          const value = JSON.stringify(data.value);

          if (value === undefined || value.length > 10000) {
            return json({ error: "Wert zu groß oder ungültig." }, 400);
          }

          await env.DB.prepare(`
            INSERT INTO user_settings (user_id, key, value)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, key)
            DO UPDATE SET
              value = excluded.value,
              updated_at = CURRENT_TIMESTAMP
          `).bind(user.id, data.key, value).run();

          return json({ success: true });
        }

        return json({ error: "API-Endpunkt nicht gefunden." }, 404);
      } catch (error) {
        console.error("NEXUS API error:", error);
        return json({ error: "Interner Serverfehler." }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  }
};
