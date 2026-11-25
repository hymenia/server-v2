import type { Context } from "hono";
import { Hono } from "hono";
import { sql } from "../../db/client.ts";
import { getAuthUser } from "../../services/auth.ts";
import { isDisposableEmail } from "../../services/disposable-email.ts";
import { createEmailVerification, verifyEmailForUser } from "../../services/email.ts";
import { createSignedEvent } from "../../services/federation.ts";
import { hashPassword, verifyPassword } from "../../services/password.ts";
import { rateLimit } from "../../services/rate-limit.ts";

const app = new Hono();

const MAX_AVATAR_BYTES = 500 * 1024;
const AVATAR_DATA_URL = /^data:image\/(png|jpe?g|webp|gif);base64,([A-Za-z0-9+/=]+)$/;

interface ProfileRow {
    id: string;
    username: string;
    display_name: string | null;
    bio: string | null;
    avatar_url: string | null;
    global_roles: string[];
    email: string | null;
    email_verified_at: string | Date | null;
}

function toProfileDto(row: ProfileRow) {
    return {
        id: row.id,
        username: row.username,
        displayName: row.display_name,
        bio: row.bio,
        avatarUrl: row.avatar_url,
        globalRoles: row.global_roles ?? [],
        email: row.email,
        emailVerified: Boolean(row.email_verified_at),
    };
}

async function readJson(c: Context): Promise<Record<string, unknown> | null> {
    try {
        const body = await c.req.json();
        if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
        return body as Record<string, unknown>;
    } catch {
        return null;
    }
}

async function isBot(userId: string): Promise<boolean> {
    const rows = await sql<{ is_bot: boolean }[]>`
        select is_bot from users where id = ${userId}::uuid limit 1
    `;
    return rows[0]?.is_bot === true;
}

function validateAvatarDataUrl(value: unknown): string | null {
    if (typeof value !== "string") return "an image is required";

    const match = value.match(AVATAR_DATA_URL);
    if (!match) return "unsupported image format";

    const approxBytes = ((match[2] ?? "").length * 3) / 4;
    if (approxBytes > MAX_AVATAR_BYTES) return "image must be smaller than 500kb";

    return null;
}

// GET /v2/account/profile
app.get("/profile", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        const rows = await sql<ProfileRow[]>`
            select id, username, display_name, bio, avatar_url, global_roles, email, email_verified_at
            from users
            where id = ${auth.user.id}::uuid
            limit 1
        `;

        const row = rows[0];
        if (!row) return c.json({ error: "User not found" }, 404);

        c.header("Cache-Control", "no-store");
        return c.json({ profile: toProfileDto(row) });
    } catch (error) {
        console.error("Profile lookup failed:", error);
        return c.json({ error: "Could not load profile" }, 500);
    }
});

// PATCH /v2/account/profile
app.patch("/profile", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        if (await isBot(auth.user.id)) {
            return c.json({ error: "Apps cannot manage account settings" }, 403);
        }

        const body = await readJson(c);
        if (!body) return c.json({ error: "Invalid request body" }, 400);

        const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
        const bio = typeof body.bio === "string" ? body.bio.trim() : "";

        if (displayName.length > 80) {
            return c.json({ error: "Display name must be 80 characters or fewer" }, 400);
        }

        if (bio.length > 500) {
            return c.json({ error: "Bio must be 500 characters or fewer" }, 400);
        }

        const rows = await sql<ProfileRow[]>`
            update users
            set display_name = nullif(${displayName}, ''),
                bio = nullif(${bio}, ''),
                updated_at = now()
            where id = ${auth.user.id}::uuid
            returning id, username, display_name, bio, avatar_url, global_roles, email, email_verified_at
        `;

        const row = rows[0];
        if (!row) return c.json({ error: "User not found" }, 404);

        c.header("Cache-Control", "no-store");
        return c.json({ profile: toProfileDto(row) });
    } catch (error) {
        console.error("Profile update failed:", error);
        return c.json({ error: "Could not update profile" }, 500);
    }
});

// POST /v2/account/password
app.post("/password", rateLimit({ bucket: "account-password", limit: 5, windowMs: 15 * 60 * 1000 }), async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        if (await isBot(auth.user.id)) {
            return c.json({ error: "Apps cannot manage account settings" }, 403);
        }

        const body = await readJson(c);
        if (!body) return c.json({ error: "Invalid request body" }, 400);

        const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
        const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";

        if (
            currentPassword.length === 0 ||
            newPassword.length < 8 ||
            newPassword.length > 200 ||
            new TextEncoder().encode(newPassword).length > 1024
        ) {
            return c.json({ error: "Current password and a new password of 8 to 200 characters are required" }, 400);
        }

        const rows = await sql<{ password_hash: string | null }[]>`
            select password_hash from users where id = ${auth.user.id}::uuid limit 1
        `;

        const stored = rows[0]?.password_hash;
        if (!stored) return c.json({ error: "User not found" }, 404);

        if (!(await verifyPassword(currentPassword, stored))) {
            return c.json({ error: "Incorrect current password" }, 401);
        }

        await sql`
            update users
            set password_hash = ${await hashPassword(newPassword)},
                updated_at = now()
            where id = ${auth.user.id}::uuid
        `;

        c.header("Cache-Control", "no-store");
        return c.json({ message: "Password updated successfully" });
    } catch (error) {
        console.error("Password update failed:", error);
        return c.json({ error: "Could not update password" }, 500);
    }
});

// POST /v2/account/delete
app.post("/delete", rateLimit({ bucket: "account-delete", limit: 5, windowMs: 15 * 60 * 1000 }), async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        if (await isBot(auth.user.id)) {
            return c.json({ error: "Apps cannot manage account settings" }, 403);
        }

        const body = await readJson(c);
        if (!body) return c.json({ error: "Invalid request body" }, 400);

        const password = typeof body.password === "string" ? body.password : "";
        if (password.length === 0) {
            return c.json({ error: "Password confirmation is required" }, 400);
        }

        const rows = await sql<{ password_hash: string | null; global_roles: string[] }[]>`
            select password_hash, global_roles from users where id = ${auth.user.id}::uuid limit 1
        `;

        const row = rows[0];
        if (!row?.password_hash) return c.json({ error: "User not found" }, 404);

        if (!(await verifyPassword(password, row.password_hash))) {
            return c.json({ error: "Incorrect password" }, 401);
        }

        if ((row.global_roles ?? []).includes("admin")) {
            const remaining = await sql<{ total: number }[]>`
                select count(*)::int as total
                from users
                where not is_bot
                  and id <> ${auth.user.id}::uuid
                  and global_roles @> array['admin']::text[]
            `;

            if ((remaining[0]?.total ?? 0) === 0) {
                return c.json({ error: "Promote another admin before deleting the last admin account" }, 400);
            }
        }

        const actorId = auth.actor.id;
        const actorUri = auth.actor.actor_uri;

        await sql.begin(async tx => {
            const owned = await tx<{ id: string; federation_uri: string }[]>`
                select id, federation_uri from "v2".spaces
                where owner_actor_id = ${actorId}::uuid
                  and is_deleted = false
                for update
            `;

            for (const space of owned) {
                const eventId = crypto.randomUUID();

                const updated = await tx<{ revision: number }[]>`
                    update "v2".spaces
                    set is_deleted = true,
                        revision = revision + 1,
                        updated_at = now()
                    where id = ${space.id}::uuid
                    returning revision
                `;

                const signedEvent = await createSignedEvent("space.deleted", eventId, space.federation_uri, actorUri, {
                    space_id: space.id,
                    revision: Number(updated[0]?.revision ?? 1),
                });

                await tx`
                    insert into "v2".federation_outbox (
                        event_id, event_type, object_uri, actor_uri, payload
                    )
                    values (
                        ${eventId}::uuid,
                        'space.deleted',
                        ${space.federation_uri},
                        ${actorUri},
                        ${tx.json(signedEvent)}
                    )
                `;
            }

            await tx`
                update "v2".messages
                set deleted_at = now()
                where author_actor_id = ${actorId}::uuid
                  and deleted_at is null
            `;

            // channels the account made in other spaces stay, owned by that space owner
            await tx`
                update "v2".channels c
                set created_by_actor_id = s.owner_actor_id
                from "v2".spaces s
                where c.space_id = s.id
                  and c.created_by_actor_id = ${actorId}::uuid
            `;

            await tx`delete from "v2".space_member_roles where actor_id = ${actorId}::uuid`;
            await tx`delete from "v2".space_members where actor_id = ${actorId}::uuid`;
            await tx`delete from "v2".space_invites where created_by_actor_id = ${actorId}::uuid`;

            // the actor row stays so the uri is never reused by a new signup
            await tx`
                update "v2".actors
                set is_active = false,
                    local_user_id = null,
                    updated_at = now()
                where id = ${actorId}::uuid
            `;

            await tx`delete from users where id = ${auth.user.id}::uuid`;
        });

        c.header("Set-Cookie", "__Host-hymenia_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
        c.header("Cache-Control", "no-store");
        return c.json({ message: "Account deleted successfully" });
    } catch (error) {
        console.error("Account delete failed:", error);
        return c.json({ error: "Could not delete account" }, 500);
    }
});

// GET /v2/account/email
app.get("/email", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        const rows = await sql<{ email: string | null; email_verified_at: string | Date | null }[]>`
            select email, email_verified_at from users where id = ${auth.user.id}::uuid limit 1
        `;

        const row = rows[0];
        if (!row) return c.json({ error: "User not found" }, 404);

        c.header("Cache-Control", "no-store");
        return c.json({
            email: row.email,
            verified: Boolean(row.email_verified_at),
            verifiedAt: row.email_verified_at ? new Date(row.email_verified_at).toISOString() : null,
        });
    } catch (error) {
        console.error("Email lookup failed:", error);
        return c.json({ error: "Could not load email" }, 500);
    }
});

// POST /v2/account/email
app.post("/email", rateLimit({ bucket: "account-email", limit: 3, windowMs: 15 * 60 * 1000 }), async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        if (await isBot(auth.user.id)) {
            return c.json({ error: "Apps cannot manage account settings" }, 403);
        }

        const body = await readJson(c);
        if (!body) return c.json({ error: "Invalid request body" }, 400);

        const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";

        if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return c.json({ error: "A valid email address is required" }, 400);
        }

        if (await isDisposableEmail(email)) {
            return c.json({ error: "Disposable or temporary email addresses are not allowed" }, 400);
        }

        const taken = await sql`
            select 1 from users
            where lower(email) = ${email}
              and id <> ${auth.user.id}::uuid
            limit 1
        `;

        if (taken.length > 0) {
            return c.json({ error: "Email already in use" }, 409);
        }

        const previous = await sql<{ email: string | null; email_verified_at: string | Date | null }[]>`
            select email, email_verified_at from users where id = ${auth.user.id}::uuid limit 1
        `;

        const before = previous[0];

        await sql`
            update users
            set email = ${email},
                email_verified_at = null,
                updated_at = now()
            where id = ${auth.user.id}::uuid
        `;

        try {
            await createEmailVerification(sql, auth.user.id, email);
        } catch (error) {
            console.error("Verification email could not be sent:", error);

            // put the old address back so a failed send does not leave an unverified account
            await sql`
                update users
                set email = ${before?.email ?? null},
                    email_verified_at = ${before?.email_verified_at ?? null},
                    updated_at = now()
                where id = ${auth.user.id}::uuid
            `;

            // the token for the address that was never confirmed is useless now
            await sql`
                delete from email_verification_tokens
                where user_id = ${auth.user.id}::uuid
            `;

            return c.json({ error: "Could not send verification email" }, 500);
        }

        c.header("Cache-Control", "no-store");
        return c.json({ message: "Verification email sent", email });
    } catch (error) {
        console.error("Email update failed:", error);
        return c.json({ error: "Could not update email" }, 500);
    }
});

// POST /v2/account/email/verify
app.post("/email/verify", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        if (await isBot(auth.user.id)) {
            return c.json({ error: "Apps cannot manage account settings" }, 403);
        }

        const body = await readJson(c);
        if (!body) return c.json({ error: "Invalid request body" }, 400);

        const token = typeof body.token === "string" ? body.token.trim() : "";
        if (!token) return c.json({ error: "Verification token is required" }, 400);

        const verified = await verifyEmailForUser(sql, auth.user.id, token);
        if (!verified) {
            return c.json({ error: "Invalid or expired token" }, 401);
        }

        const rows = await sql<{ email: string | null }[]>`
            select email from users where id = ${auth.user.id}::uuid limit 1
        `;

        const email = rows[0]?.email ?? null;

        if (email && (await isDisposableEmail(email))) {
            await sql`
                update users
                set email = null, email_verified_at = null, updated_at = now()
                where id = ${auth.user.id}::uuid
            `;

            return c.json({ error: "Disposable or temporary email addresses are not allowed" }, 400);
        }

        c.header("Cache-Control", "no-store");
        return c.json({ message: "Email verified", email });
    } catch (error) {
        console.error("Email verify failed:", error);
        return c.json({ error: "Could not verify email" }, 500);
    }
});

// POST /v2/account/avatar
app.post("/avatar", rateLimit({ bucket: "account-avatar", limit: 10, windowMs: 15 * 60 * 1000 }), async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        const body = await readJson(c);
        if (!body) return c.json({ error: "Invalid request body" }, 400);

        const avatarUrl = body.avatarUrl;
        const invalid = validateAvatarDataUrl(avatarUrl);
        if (invalid) return c.json({ error: invalid }, 400);

        await sql`
            update users
            set avatar_url = ${avatarUrl as string}, updated_at = now()
            where id = ${auth.user.id}::uuid
        `;

        c.header("Cache-Control", "no-store");
        return c.json({ avatarUrl });
    } catch (error) {
        console.error("Avatar update failed:", error);
        return c.json({ error: "Could not update avatar" }, 500);
    }
});

// POST /v2/account/avatar/delete
app.post("/avatar/delete", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        await sql`
            update users
            set avatar_url = null, updated_at = now()
            where id = ${auth.user.id}::uuid
        `;

        c.header("Cache-Control", "no-store");
        return c.json({ message: "Avatar removed" });
    } catch (error) {
        console.error("Avatar delete failed:", error);
        return c.json({ error: "Could not remove avatar" }, 500);
    }
});

export default app;
