import type { Context } from "hono";
import { Hono } from "hono";
import { SERVER_DOMAIN, SERVER_ORIGIN } from "../../config/server.ts";
import { sql } from "../../db/client.ts";
import { createAltchaChallenge, verifyAltchaPayload } from "../../services/altcha.ts";
import { COOKIE, findUser, hash, type PublicUser, readToken } from "../../services/auth.ts";
import { createEmailVerification, verifyEmail } from "../../services/email.ts";
import { hashPassword, isBcryptHash, verifyPassword } from "../../services/password.ts";
import { rateLimit } from "../../services/rate-limit.ts";

const auth = new Hono();

const SESSION_DAYS = 14;

interface UserCredentialsRow extends PublicUser {
    password_hash: string;
    email_verified_at: string | Date | null;
}

interface RegisterBody {
    username?: unknown;
    email?: unknown;
    password?: unknown;
    altcha?: unknown;
}

interface LoginBody {
    login?: unknown;
    password?: unknown;
    altcha?: unknown;
}

function normalizeUsername(value: string): string {
    return value.trim().toLowerCase();
}

function isValidUsername(username: string): boolean {
    return /^[a-z0-9_]+(?:\.[a-z0-9_]+)*$/.test(username) && username.length >= 3 && username.length <= 30;
}

function randomToken(): string {
    return Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, "0")).join("");
}

function setCookie(c: Context, token: string) {
    c.header(
        "Set-Cookie",
        `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`,
    );
}

function clearCookie(c: Context) {
    c.header("Set-Cookie", `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
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

// GET /v2/auth/altcha/challenge
auth.get("/altcha/challenge", async c => {
    try {
        const challenge = await createAltchaChallenge();

        if (!challenge) {
            return c.json({ error: "Captcha is not configured" }, 503);
        }

        c.header("Cache-Control", "no-store");
        return c.json(challenge);
    } catch (error) {
        console.error("Altcha challenge failed:", error);
        return c.json({ error: "Could not create challenge" }, 500);
    }
});

// POST /v2/auth/register
auth.post("/register", rateLimit({ bucket: "register", limit: 5, windowMs: 15 * 60 * 1000 }), async c => {
    let body: RegisterBody;

    try {
        body = (await c.req.json()) as RegisterBody;
    } catch {
        return c.json({ error: "Invalid JSON" }, 400);
    }

    if (typeof body !== "object" || body === null || Array.isArray(body)) {
        return c.json({ error: "Invalid request body" }, 400);
    }

    const username = typeof body.username === "string" ? normalizeUsername(body.username) : "";

    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";

    const password = typeof body.password === "string" ? body.password : "";

    if (
        !isValidUsername(username) ||
        !email ||
        email.length > 254 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        password.length < 12 ||
        new TextEncoder().encode(password).length > 1024
    ) {
        return c.json(
            {
                error: "Provide a valid username, email, and password of at least 12 characters",
            },
            400,
        );
    }

    if (!(await verifyAltchaPayload(body.altcha))) {
        return c.json({ error: "Captcha verification failed" }, 400);
    }

    const passwordHash = await hashPassword(password);
    const actorUri = `${SERVER_ORIGIN}/actors/${username}`;

    try {
        const user = await sql.begin(async tx => {
            const rows = await tx<PublicUser[]>`
      INSERT INTO users (username, email, password_hash)
      VALUES (
        ${username},
        ${email},
        ${passwordHash}
      )
      RETURNING id, username, email
    `;

            const inserted = rows[0];

            if (!inserted) {
                throw new Error("User INSERT returned no row");
            }

            // every local user needs an actor row, or every /v2 route doesnt work
            await tx`
        INSERT INTO "v2".actors (actor_uri, host, username, local_user_id)
        VALUES (
          ${actorUri},
          ${SERVER_DOMAIN.toLowerCase()},
          ${username},
          ${inserted.id}::uuid
        )
      `;

            return inserted;
        });

        try {
            await createEmailVerification(sql, user.id, email);
        } catch (error) {
            console.error("Verification email could not be sent:", error);

            return c.json(
                {
                    error: "Account created, but the verification email could not be sent.",
                },
                503,
            );
        }

        c.header("Cache-Control", "no-store");

        return c.json(
            {
                message: "Account created. Check your email to verify your address.",
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                },
            },
            201,
        );
    } catch (error) {
        if (error && typeof error === "object" && "code" in error && error.code === "23505") {
            return c.json({ error: "Username or email already exists" }, 409);
        }

        console.error("Registration failed:", error);
        return c.json({ error: "Registration failed" }, 500);
    }
});

// POST /v2/auth/login
auth.post("/login", rateLimit({ bucket: "login", limit: 10, windowMs: 15 * 60 * 1000 }), async c => {
    let body: LoginBody;

    try {
        body = (await c.req.json()) as LoginBody;
    } catch {
        return c.json({ error: "Invalid JSON" }, 400);
    }

    const loginInput = typeof body?.login === "string" ? body.login : "";
    const password = typeof body?.password === "string" ? body.password : "";

    if (loginInput.trim().length === 0 || loginInput.length > 254 || password.length > 1024) {
        return c.json({ error: "Invalid username/email or password" }, 401);
    }

    if (!(await verifyAltchaPayload(body?.altcha))) {
        return c.json({ error: "Captcha verification failed" }, 400);
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

        // upgrade a v1 bcrypt hash to the v2 format on the first successful login
        if (isBcryptHash(user.password_hash)) {
            try {
                await sql`
          UPDATE users
          SET password_hash = ${await hashPassword(password)}
          WHERE id = ${user.id}
        `;
            } catch (error) {
                console.error("Password rehash failed:", error);
            }
        }

        if (!user.email_verified_at) {
            return c.json(
                {
                    error: "Please verify your email address before logging in.",
                    code: "EMAIL_NOT_VERIFIED",
                },
                403,
            );
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
auth.get("/me", async c => {
    try {
        const user = await findUser(c);

        c.header("Cache-Control", "no-store");

        return user ? c.json({ user }) : c.json({ error: "Not authenticated" }, 401);
    } catch (error) {
        console.error("Session lookup failed:", error);
        return c.json({ error: "Authentication temporarily unavailable" }, 500);
    }
});

// POST /v2/auth/logout
auth.post("/logout", async c => {
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

// POST /v2/auth/resend-verification
auth.post("/resend-verification", rateLimit({ bucket: "resend", limit: 3, windowMs: 15 * 60 * 1000 }), async c => {
    let body: { email?: unknown };

    try {
        body = (await c.req.json()) as { email?: unknown };
    } catch {
        return c.json({ error: "Invalid JSON" }, 400);
    }

    const email = typeof body?.email === "string" ? body.email.trim().toLowerCase() : "";

    if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return c.json({ error: "Provide a valid email address" }, 400);
    }

    c.header("Cache-Control", "no-store");

    try {
        const rows = await sql<{ id: string; email: string }[]>`
      SELECT id, email
      FROM users
      WHERE LOWER(email) = ${email}
        AND email_verified_at IS NULL
      LIMIT 1
    `;

        const user = rows[0];

        if (user?.email) {
            await createEmailVerification(sql, user.id, user.email);
        }
    } catch (error) {
        console.error("Resend verification failed:", error);
    }

    // same answer either way so this does not reveal which accounts exist
    return c.json({
        message: "If that address needs verification, a new link has been sent.",
    });
});

// GET /v2/auth/verify-email?token=...
auth.get("/verify-email", async c => {
    const token = c.req.query("token");

    if (!token || !/^[0-9a-f]{64}$/.test(token)) {
        return c.json(
            {
                error: "Invalid or expired verification link.",
            },
            400,
        );
    }

    try {
        const verified = await verifyEmail(sql, token);

        if (!verified) {
            return c.json(
                {
                    error: "Invalid or expired verification link.",
                },
                400,
            );
        }

        c.header("Cache-Control", "no-store");

        return c.json({
            message: "Email address verified successfully. You can now log in.",
        });
    } catch (error) {
        console.error("Email verification failed:", error);

        return c.json(
            {
                error: "Email verification is temporarily unavailable.",
            },
            500,
        );
    }
});

export default auth;
