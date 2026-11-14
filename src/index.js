
const SESSION_DAYS = 30;
const PASSWORD_ITERATIONS = 100000;
const TOTP_PERIOD = 30;
const TOTP_DIGITS = 6;
const PENDING_MINUTES = 15;

function json(data, status = 200, headers = {}) {
  return Response.json(data, { status, headers });
}

function randomHex(bytes = 32) {
  const array = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(array, b =>
    b.toString(16).padStart(2, "0")
  ).join("");
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

  return await env.DB.prepare(`
    SELECT users.id, users.username
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
      AND sessions.expires_at > ?
  `).bind(tokenHash, now).first();
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

/* ==================================
   BASE32 FÜR AUTHENTICATOR
================================== */

const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let output = "";

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      output += BASE32_CHARS[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_CHARS[(value << (5 - bits)) & 31];
  }

  return output;
}

function base32Decode(input) {
  const text = input.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const output = [];

  for (const char of text) {
    const index = BASE32_CHARS.indexOf(char);

    if (index < 0) {
      throw new Error("Ungültiger Authenticator-Schlüssel.");
    }

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}

/* ==================================
   AUTHENTICATOR-VERSCHLÜSSELUNG
================================== */

function hexToBytes(hex) {
  if (!/^[a-fA-F0-9]{64}$/.test(hex || "")) {
    throw new Error(
      "NEXUS_TOTP_ENCRYPTION_KEY fehlt oder ist ungültig."
    );
  }

  const bytes = new Uint8Array(32);

  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }

  return bytes;
}

function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);

  return Uint8Array.from(binary, char =>
    char.charCodeAt(0)
  );
}

async function getEncryptionKey(env) {
  return crypto.subtle.importKey(
    "raw",
    hexToBytes(env.NEXUS_TOTP_ENCRYPTION_KEY),
    "AES-GCM",
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptSecret(secret, env) {
  const key = await getEncryptionKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(secret)
  );

  return JSON.stringify({
    iv: bytesToBase64(iv),
    data: bytesToBase64(new Uint8Array(encrypted))
  });
}

async function decryptSecret(encryptedValue, env) {
  const key = await getEncryptionKey(env);
  const stored = JSON.parse(encryptedValue);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBytes(stored.iv)
    },
    key,
    base64ToBytes(stored.data)
  );

  return new TextDecoder().decode(decrypted);
}

/* ==================================
   TOTP-CODE PRÜFEN
================================== */

async function generateTotp(secret, step) {
  const key = await crypto.subtle.importKey(
    "raw",
    base32Decode(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );

  const counter = new Uint8Array(8);
  let value = step;

  for (let i = 7; i >= 0; i--) {
    counter[i] = value & 255;
    value = Math.floor(value / 256);
  }

  const hash = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, counter)
  );

  const offset = hash[hash.length - 1] & 15;

  const binary =
    ((hash[offset] & 127) << 24) |
    ((hash[offset + 1] & 255) << 16) |
    ((hash[offset + 2] & 255) << 8) |
    (hash[offset + 3] & 255);

  return String(binary % (10 ** TOTP_DIGITS))
    .padStart(TOTP_DIGITS, "0");
}

async function verifyTotp(secret, code) {
  if (!/^\d{6}$/.test(String(code || ""))) {
    return null;
  }

  const currentStep = Math.floor(Date.now() / 1000 / TOTP_PERIOD);

  for (const offset of [-1, 0, 1]) {
    const step = currentStep + offset;
    const expected = await generateTotp(secret, step);

    if (expected === code) {
      return step;
    }
  }

  return null;
}

/* ==================================
   BENUTZER ERSTELLEN
================================== */

async function createUser(username, passwordHash, salt, env) {
  const userId = crypto.randomUUID();

  await env.DB.prepare(`
    INSERT INTO users (id, username, password_hash, password_salt)
    VALUES (?, ?, ?, ?)
  `).bind(userId, username, passwordHash, salt).run();

  const count = await env.DB.prepare(
    "SELECT COUNT(*) AS total FROM users"
  ).first();

  if (count.total === 1) {
    await env.DB.prepare(`
      INSERT INTO user_settings (user_id, key, value)
      SELECT ?, key, value FROM settings
      WHERE 1
      ON CONFLICT(user_id, key)
      DO NOTHING
    `).bind(userId).run();
  }

  return userId;
}

function safeInviteCodeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);

  for (let i = 0; i < length; i++) {
    difference |=
      (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }

  return difference === 0;
}

/* ==================================
   API
================================== */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {

      /* REGISTRIERUNG */

      if (path === "/api/auth/register" && request.method === "POST") {
        const data = await request.json();

        const username = String(data.username || "").trim();
        const password = String(data.password || "");
        const method = String(data.method || "");

        if (!/^[a-zA-Z0-9_-]{3,20}$/.test(username)) {
          return json({
            error: "Benutzername: 3–20 Zeichen, nur Buchstaben, Zahlen, _ und -."
          }, 400);
        }

        if (password.length < 8 || password.length > 128) {
          return json({
            error: "Das Passwort muss 8–128 Zeichen lang sein."
          }, 400);
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM users WHERE username = ?"
        ).bind(username).first();

        if (existing) {
          return json({
            error: "Dieser Benutzername ist bereits vergeben."
          }, 409);
        }

        const passwordSalt = randomHex(16);
        const passwordHash = await hashPassword(password, passwordSalt);

        /* METHODE 1: EINLADUNGSCODE */

        if (method === "invite") {
          if (!env.NEXUS_INVITE_CODE) {
            return json({
              error: "Die Einladungscode-Registrierung ist nicht eingerichtet."
            }, 503);
          }

          if (!safeInviteCodeEqual(
            String(data.inviteCode || ""),
            env.NEXUS_INVITE_CODE
          )) {
            return json({
              error: "Der Einladungscode ist ungültig."
            }, 403);
          }

          const userId = await createUser(
            username,
            passwordHash,
            passwordSalt,
            env
          );

          const token = await createSession(userId, env);

          return json(
            { success: true, username },
            201,
            { "Set-Cookie": sessionCookie(token) }
          );
        }

        /* METHODE 2: AUTHENTICATOR */

        if (method === "authenticator") {
          if (!env.NEXUS_TOTP_ENCRYPTION_KEY) {
            return json({
              error: "Die Authenticator-Verschlüsselung ist nicht eingerichtet."
            }, 503);
          }

          await env.DB.prepare(`
            DELETE FROM pending_auth_registrations
            WHERE expires_at <= ?
          `).bind(Math.floor(Date.now() / 1000)).run();

          const pending = await env.DB.prepare(`
            SELECT id FROM pending_auth_registrations
            WHERE username = ?
          `).bind(username).first();

          if (pending) {
            await env.DB.prepare(`
              DELETE FROM pending_auth_registrations
              WHERE username = ?
            `).bind(username).run();
          }

          const secret = base32Encode(
            crypto.getRandomValues(new Uint8Array(20))
          );

          const encryptedSecret = await encryptSecret(secret, env);

          const expiresAt = Math.floor(Date.now() / 1000)
            + PENDING_MINUTES * 60;

          await env.DB.prepare(`
            INSERT INTO pending_auth_registrations
              (id, username, password_hash, password_salt,
               encrypted_secret, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind(
            crypto.randomUUID(),
            username,
            passwordHash,
            passwordSalt,
            encryptedSecret,
            expiresAt
          ).run();

          return json({
            success: true,
            setupRequired: true,
            username,
            secret,
            algorithm: "SHA1",
            digits: 6,
            period: 30,
            expiresInMinutes: PENDING_MINUTES
          }, 201);
        }

        return json({
          error: "Bitte Authenticator oder Einladungscode auswählen."
        }, 400);
      }

      /* AUTHENTICATOR EINRICHTUNG BESTÄTIGEN */

      if (
        path === "/api/auth/register/verify" &&
        request.method === "POST"
      ) {
        const data = await request.json();
        const username = String(data.username || "").trim();
        const code = String(data.code || "");

        const pending = await env.DB.prepare(`
          SELECT *
          FROM pending_auth_registrations
          WHERE username = ?
        `).bind(username).first();

        if (!pending) {
          return json({
            error: "Keine offene Authenticator-Einrichtung gefunden."
          }, 404);
        }

        if (pending.expires_at <= Math.floor(Date.now() / 1000)) {
          await env.DB.prepare(`
            DELETE FROM pending_auth_registrations WHERE id = ?
          `).bind(pending.id).run();

          return json({
            error: "Die Einrichtung ist abgelaufen. Bitte beginne erneut."
          }, 400);
        }

        const secret = await decryptSecret(
          pending.encrypted_secret,
          env
        );

        const matchedStep = await verifyTotp(secret, code);

        if (matchedStep === null) {
          return json({
            error: "Der Authenticator-Code ist falsch oder abgelaufen."
          }, 401);
        }

        const userId = await createUser(
          pending.username,
          pending.password_hash,
          pending.password_salt,
          env
        );

        await env.DB.prepare(`
          INSERT INTO user_authenticators
            (user_id, secret, enabled, last_used_step)
          VALUES (?, ?, 1, ?)
        `).bind(
          userId,
          pending.encrypted_secret,
          matchedStep
        ).run();

        await env.DB.prepare(`
          DELETE FROM pending_auth_registrations WHERE id = ?
        `).bind(pending.id).run();

        const token = await createSession(userId, env);

        return json(
          {
            success: true,
            username: pending.username
          },
          201,
          { "Set-Cookie": sessionCookie(token) }
        );
      }

      /* LOGIN */

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
          return json({
            error: "Benutzername oder Passwort falsch."
          }, 401);
        }

        const passwordHash = await hashPassword(
          password,
          user.password_salt
        );

        if (passwordHash !== user.password_hash) {
          return json({
            error: "Benutzername oder Passwort falsch."
          }, 401);
        }

        const authenticator = await env.DB.prepare(`
          SELECT secret, enabled, last_used_step
          FROM user_authenticators
          WHERE user_id = ?
        `).bind(user.id).first();

        if (authenticator && authenticator.enabled === 1) {
          const secret = await decryptSecret(
            authenticator.secret,
            env
          );

          const matchedStep = await verifyTotp(
            secret,
            String(data.code || "")
          );

          if (matchedStep === null) {
            return json({
              error: "Bitte gib deinen aktuellen Authenticator-Code ein.",
              requiresAuthenticator: true
            }, 401);
          }

          if (matchedStep <= authenticator.last_used_step) {
            return json({
              error: "Dieser Authenticator-Code wurde bereits verwendet."
            }, 401);
          }

          const update = await env.DB.prepare(`
            UPDATE user_authenticators
            SET last_used_step = ?
            WHERE user_id = ?
              AND last_used_step < ?
              AND enabled = 1
          `).bind(
            matchedStep,
            user.id,
            matchedStep
          ).run();

          if (update.meta.changes !== 1) {
            return json({
              error: "Dieser Authenticator-Code wurde bereits verwendet."
            }, 401);
          }
        }

        const token = await createSession(user.id, env);

        return json(
          {
            success: true,
            username: user.username
          },
          200,
          { "Set-Cookie": sessionCookie(token) }
        );
      }

      /* AKTUELLEN LOGIN PRÜFEN */

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

      /* LOGOUT */

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

      /* BENUTZER-EINSTELLUNGEN LADEN */

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

      /* BENUTZER-EINSTELLUNGEN SPEICHERN */

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
        `).bind(
          user.id,
          data.key,
          JSON.stringify(data.value)
        ).run();

        return json({ success: true });
      }

      return env.ASSETS.fetch(request);

    } catch (error) {
      console.error("THYQORA API error:", error);
      return json({
        error: "Interner Serverfehler."
      }, 500);
    }
  }
};
