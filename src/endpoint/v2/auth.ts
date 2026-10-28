import type { Context } from "hono";
import { Hono } from "hono";
import { sql } from "../../db/client.ts";
import { createEmailVerification, verifyEmail } from "../../services/email.ts";

const auth = new Hono();

const COOKIE = "__Host-hymenia_session";
const SESSION_DAYS = 14;

interface PublicUser {
  id: string;
  username: string;
  email: string;
}

interface UserCredentialsRow extends PublicUser {
  password_hash: string;
  email_verified_at: string | Date | null;
}

interface RegisterBody {
  username?: unknown;
  email?: unknown;
  password?: unknown;
}

interface LoginBody {
  login?: unknown;
  password?: unknown;
}

function normalizeUsername(value: string): string {
  return value.trim().toLowerCase();
}

function isValidUsername(username: string): boolean {
  return /^[a-z0-9_]+(?:\.[a-z0-9_]+)*$/.test(username) &&
    username.length >= 3 &&
    username.length <= 30;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

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
    { name: "PBKDF2", hash: "SHA-256", salt: toArrayBuffer(salt), iterations: 600_000 },
    key,
    256,
  );

  const hex = (bytes: Uint8Array) =>
    Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

  return `pbkdf2$${hex(salt)}$${hex(new Uint8Array(bits))}`;
}

async function verifyPassword(
  password: string,
  stored: string,
): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== "pbkdf2") return false;

  const saltHex = parts[1];
  const expectedHex = parts[2];

  if (
    !saltHex ||
    !expectedHex ||
    !/^[0-9a-f]{32}$/.test(saltHex) ||
    !/^[0-9a-f]{64}$/.test(expectedHex)
  ) {
    return false;
  }

  const fromHex = (value: string): Uint8Array =>
    new Uint8Array((value.match(/.{2}/g) ?? []).map((x) => parseInt(x, 16)));

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
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: toArrayBuffer(salt),
      iterations: 600_000,
    },
    key,
    256,
  );

  const actual = new Uint8Array(bits);

  let difference = actual.length ^ expected.length;

  for (let i = 0; i < Math.min(actual.length, expected.length); i++) {
    difference |= (actual[i] ?? 0) ^ (expected[i] ?? 0);
  }

  return difference === 0;
}

function setCookie(c: Context, token: string) {
  c.header(
    "Set-Cookie",
    `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${
      SESSION_DAYS *
      86400
    }`,
  );
}

function clearCookie(c: Context) {
  c.header(
    "Set-Cookie",
    `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
  );
}

function readToken(c: Context): string | null {
  const cookie = c.req.header("Cookie") ?? "";
  const prefix = `${COOKIE}=`;

  const item = cookie
    .split(";")
    .map((s) => s.trim())
    .find((s) => s.startsWith(prefix));

  const token = item?.slice(prefix.length);

  return token && /^[0-9a-f]{64}$/.test(token) ? token : null;
}

async function findUser(c: Context): Promise<PublicUser | null> {
  const token = readToken(c);
  if (!token) return null;

  const tokenHash = await hash(token);

  const rows = await sql<PublicUser[]>`
    SELECT u.id, u.username, u.email
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ${tokenHash}
      AND s.expires_at > NOW()
    LIMIT 1
  `;

  return rows[0] ?? null;
}

async function createSession(c: Context, userId: string): Promise<void> {
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
  let body: RegisterBody;

  try {
    body = (await c.req.json()) as RegisterBody;
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return c.json({ error: "Invalid request body" }, 400);
  }

  const username = typeof body.username === "string"
    ? normalizeUsername(body.username)
    : "";

  const email = typeof body.email === "string"
    ? body.email.trim().toLowerCase()
    : "";

  const password = typeof body.password === "string" ? body.password : "";

  if (
    !isValidUsername(username) ||
    !email ||
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    password.length < 12 ||
    new TextEncoder().encode(password).length > 1024
  ) {
    return c.json({
      error:
        "Provide a valid username, email, and password of at least 12 characters",
    }, 400);
  }

  try {
    const rows = await sql<PublicUser[]>`
      INSERT INTO users (username, email, password_hash)
      VALUES (
        ${username},
        ${email},
        ${await hashPassword(password)}
      )
      RETURNING id, username, email
    `;

    const user = rows[0];

    if (!user) {
      throw new Error("User INSERT returned no row");
    }

    try {
      await createEmailVerification(sql, user.id, email);
    } catch (error) {
      console.error("Verification email could not be sent:", error);

      return c.json({
        error:
          "Account created, but the verification email could not be sent.",
      }, 503);
    }

    c.header("Cache-Control", "no-store");

    return c.json({
      message: "Account created. Check your email to verify your address.",
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
    }, 201);
  } catch (error) {
    if (
      error && typeof error === "object" &&
      "code" in error && error.code === "23505"
    ) {
      return c.json({ error: "Username or email already exists" }, 409);
    }

    console.error("Registration failed:", error);
    return c.json({ error: "Registration failed" }, 500);
  }
});

// POST /v2/auth/login
auth.post("/login", async (c) => {
  let body: LoginBody;

  try {
    body = (await c.req.json()) as LoginBody;
  } catch {
    return c.json({ error: "Invalid JSON" }, 400);
  }

  const loginInput = typeof body?.login === "string" ? body.login : "";
  const password = typeof body?.password === "string" ? body.password : "";

  if (
    loginInput.trim().length === 0 ||
    loginInput.length > 254 ||
    password.length > 1024
  ) {
    return c.json({ error: "Invalid username/email or password" }, 401);
  }

  try {
    const login = loginInput.trim();
    const usernameLogin = normalizeUsername(login);
    const emailLogin = login.toLowerCase();

    const rows = await sql<UserCredentialsRow[]>`
      SELECT id, username, email, password_hash, email_verified_at
      FROM users
      WHERE username = ${usernameLogin}
         OR LOWER(email) = ${emailLogin}
      LIMIT 1
    `;

    const user = rows[0];

    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return c.json({ error: "Invalid username/email or password" }, 401);
    }

    if (!user.email_verified_at) {
      return c.json({
        error: "Please verify your email address before logging in.",
        code: "EMAIL_NOT_VERIFIED",
      }, 403);
    }

    await createSession(c, user.id);

    c.header("Cache-Control", "no-store");

    return c.json({
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Login failed:", error);
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
  } catch (error) {
    console.error("Session lookup failed:", error);
    return c.json({ error: "Authentication temporarily unavailable" }, 500);
  }
});

// POST /v2/auth/logout
auth.post("/logout", async (c) => {
  try {
    const token = readToken(c);

    if (token) {
      await sql`
        DELETE FROM sessions
        WHERE token_hash = ${await hash(token)}
      `;
    }

    clearCookie(c);
    c.header("Cache-Control", "no-store");

    return c.json({ success: true });
  } catch (error) {
    console.error("Logout failed:", error);
    return c.json({ error: "Logout failed" }, 500);
  }
});

// GET /v2/auth/verify-email?token=...
auth.get("/verify-email", async (c) => {
  const token = c.req.query("token");

  if (!token || !/^[0-9a-f]{64}$/.test(token)) {
    return c.json({
      error: "Invalid or expired verification link.",
    }, 400);
  }

  try {
    const verified = await verifyEmail(sql, token);

    if (!verified) {
      return c.json({
        error: "Invalid or expired verification link.",
      }, 400);
    }

    c.header("Cache-Control", "no-store");

    return c.json({
      message: "Email address verified successfully. You can now log in.",
    });
  } catch (error) {
    console.error("Email verification failed:", error);

    return c.json({
      error: "Email verification is temporarily unavailable.",
    }, 500);
  }
});

export default auth;