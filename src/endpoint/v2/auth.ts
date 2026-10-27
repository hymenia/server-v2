
import { Hono } from "hono";
import { sql } from "../../db/client.ts";

const auth = new Hono();

const COOKIE = "__Host-hymenia_session";
const SESSION_DAYS = 14;

function randomToken(): string {
  return Array.from(
    crypto.getRandomValues(new Uint8Array(32)),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
}

async function hash(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
}

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 600_000 },
    key,
    256,
  );

  const hex = (bytes: Uint8Array) =>
    Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

  return `pbkdf2$${hex(salt)}$${hex(new Uint8Array(bits))}`;
}

async function verifyPassword(password: string, stored: string) {
  const [, saltHex, expectedHex] = stored.split("$");
  if (!saltHex || !expectedHex) return false;

  const fromHex = (value: string) =>
    new Uint8Array(value.match(/.{2}/g)!.map((x) => parseInt(x, 16)));

  const salt = fromHex(saltHex);
  const expected = fromHex(expectedHex);
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 600_000 },
    key,
    256,
  );
  const actual = new Uint8Array(bits);

  let difference = actual.length ^ expected.length;
  for (let i = 0; i < Math.min(actual.length, expected.length); i++) {
    difference |= actual[i] ^ expected[i];
  }
  return difference === 0;
}

function setCookie(c: any, token: string) {
  c.header(
    "Set-Cookie",
    `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`,
  );
}

function clearCookie(c: any) {
  c.header(
    "Set-Cookie",
    `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
  );
}

async function readToken(c: any): Promise<string | null> {
  const cookie = c.req.header("Cookie") ?? "";
  const prefix = `${COOKIE}=`;
  const item = cookie.split(";").map((s: string) => s.trim())
    .find((s: string) => s.startsWith(prefix));
  const token = item?.slice(prefix.length);
  return token && /^[0-9a-f]{64}$/.test(token) ? token : null;
}

async function findUser(c: any) {
  const token = await readToken(c);
  if (!token) return null;

  const tokenHash = await hash(token);
  const rows = await sql`
    SELECT u.id, u.username, u.email
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ${tokenHash} AND s.expires_at > NOW()
    LIMIT 1
  `;
  return rows[0] ?? null;
}

async function createSession(c: any, userId: string) {
  const token = randomToken();
  await sql`
    INSERT INTO sessions (user_id, token_hash, expires_at)
    VALUES (
      ${userId},
      ${await hash(token)},
      NOW() + (${SESSION_DAYS} * INTERVAL '1 day')
    )
  `;
  setCookie(c, token);
}

// POST /v2/auth/register
auth.post("/register", async (c) => {
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  if (
    typeof body?.username !== "string" ||
    !/^[a-zA-Z0-9_]{3,30}$/.test(body.username) ||
    typeof body?.email !== "string" ||
    body.email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email) ||
    typeof body?.password !== "string" ||
    body.password.length < 12 ||
    new TextEncoder().encode(body.password).length > 1024
  ) {
    return c.json({
      error: "Provide a valid username, email, and password of at least 12 characters",
    }, 400);
  }

  try {
    const rows = await sql`
      INSERT INTO users (username, email, password_hash)
      VALUES (
        ${body.username},
        ${body.email.trim().toLowerCase()},
        ${await hashPassword(body.password)}
      )
      RETURNING id, username, email
    `;

    await createSession(c, rows[0].id);
    c.header("Cache-Control", "no-store");
    return c.json({ user: rows[0] }, 201);
  } catch (error) {
    if (
      error && typeof error === "object" && "code" in error &&
      error.code === "23505"
    ) {
      return c.json({ error: "Username or email already exists" }, 409);
    }
     console.error("Registration failed:", error);
    return c.json({ error: "Registration failed" }, 500);
  }
});

// POST /v2/auth/login
auth.post("/login", async (c) => {
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  if (
    typeof body?.login !== "string" ||
    body.login.length > 254 ||
    typeof body?.password !== "string" ||
    body.password.length > 1024
  ) {
    return c.json({ error: "Invalid username/email or password" }, 401);
  }

  try {
    const rows = await sql`
      SELECT id, username, email, password_hash FROM users
      WHERE LOWER(username) = LOWER(${body.login})
         OR LOWER(email) = LOWER(${body.login})
      LIMIT 1
    `;
    const user = rows[0];

    if (!user || !(await verifyPassword(body.password, user.password_hash))) {
      return c.json({ error: "Invalid username/email or password" }, 401);
    }

    await createSession(c, user.id);
    c.header("Cache-Control", "no-store");
    return c.json({
      user: { id: user.id, username: user.username, email: user.email },
    });
  } catch {
    console.error("Login failed");
    return c.json({ error: "Login temporarily unavailable" }, 500);
  }
});

// GET /v2/auth/me
auth.get("/me", async (c) => {
  try {
    const user = await findUser(c);
    c.header("Cache-Control", "no-store");
    return user
      ? c.json({ user })
      : c.json({ error: "Not authenticated" }, 401);
  } catch {
    console.error("Session lookup failed");
    return c.json({ error: "Authentication temporarily unavailable" }, 500);
  }
});

// POST /v2/auth/logout
auth.post("/logout", async (c) => {
  try {
    const token = await readToken(c);
    if (token) {
      await sql`DELETE FROM sessions WHERE token_hash = ${await hash(token)}`;
    }
    clearCookie(c);
    c.header("Cache-Control", "no-store");
    return c.json({ success: true });
  } catch {
    console.error("Logout failed");
    return c.json({ error: "Logout failed" }, 500);
  }
});

export default auth;
