import { Hono } from "hono";
import { SERVER_DOMAIN } from "../../config/server.ts";
import { sql } from "../../db/client.ts";
import { getAuthUser } from "../../services/auth.ts";

const app = new Hono();

const GLOBAL_ROLES = new Set(["verified", "developer", "contributor"]);

interface PublicUser {
    id: string;
    username: string;
    display_name: string | null;
    bio: string | null;
    is_bot: boolean;
    global_roles: string[];
    created_at: string | Date;
}

interface RemoteActor {
    id: string;
    username: string;
    host: string;
    display_name: string | null;
    actor_type: string;
    created_at: string | Date;
}

function normalizeUsername(value: string): string {
    return value.trim().toLowerCase();
}

function isValidUsername(username: string): boolean {
    return /^[a-z0-9_]+(?:\.[a-z0-9_]+)*$/.test(username) && username.length >= 3 && username.length <= 30;
}

function isValidHost(host: string): boolean {
    return /^[a-z0-9.-]+(?::\d{1,5})?$/.test(host) && host.length <= 253;
}

// GET /v2/users/:username, or :username@host for a remote actor
app.get("/:username", async c => {
    const raw = c.req.param("username").trim().toLowerCase();
    const at = raw.lastIndexOf("@");

    const username = normalizeUsername(at === -1 ? raw : raw.slice(0, at));
    const host = at === -1 ? null : raw.slice(at + 1);

    if (!isValidUsername(username)) {
        return c.json({ error: "Invalid username" }, 400);
    }

    if (host !== null && !isValidHost(host)) {
        return c.json({ error: "Invalid host" }, 400);
    }

    try {
        if (host !== null) {
            const rows = await sql<RemoteActor[]>`
                SELECT id, username, host, display_name, actor_type, created_at
                FROM "v2".actors
                WHERE host = ${host}
                  AND username = ${username}
                  AND is_active = TRUE
                LIMIT 1
            `;

            const actor = rows[0];

            if (!actor) {
                return c.json({ error: "User not found" }, 404);
            }

            c.header("Cache-Control", "public, max-age=60");

            return c.json({
                user: {
                    id: actor.id,
                    username: actor.username,
                    host: actor.host,
                    display_name: actor.display_name,
                    bio: null,
                    is_bot: actor.actor_type === "bot",
                    global_roles: [],
                    created_at: actor.created_at,
                    address: `${actor.username}@${actor.host}`,
                },
            });
        }

        const rows = await sql<PublicUser[]>`
            SELECT id, username, display_name, bio, is_bot, global_roles, created_at
            FROM users
            WHERE username = ${username}
            LIMIT 1
        `;

        const user = rows[0];

        if (!user) {
            return c.json({ error: "User not found" }, 404);
        }

        c.header("Cache-Control", "public, max-age=60");

        return c.json({
            user: {
                ...user,
                host: null,
                address: `${user.username}@${SERVER_DOMAIN}`,
            },
        });
    } catch (error) {
        console.error("User lookup failed:", error);
        return c.json({ error: "User lookup temporarily unavailable" }, 500);
    }
});

// PATCH /v2/users/:username/roles
app.patch("/:username/roles", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        const me = await sql<{ global_roles: string[] }[]>`
            select global_roles from users where id = ${auth.user.id}::uuid limit 1
        `;

        if (!(me[0]?.global_roles ?? []).includes("developer")) {
            return c.json({ error: "Developer role required" }, 403);
        }

        const username = normalizeUsername(c.req.param("username"));
        if (!isValidUsername(username)) {
            return c.json({ error: "Invalid username" }, 400);
        }

        let body: unknown;
        try {
            body = await c.req.json();
        } catch {
            return c.json({ error: "Invalid request body" }, 400);
        }

        const rawRoles = (body as { roles?: unknown } | null)?.roles;
        if (!Array.isArray(rawRoles)) {
            return c.json({ error: "Roles must be an array containing only verified, developer or contributor" }, 400);
        }

        const roles = [...new Set(rawRoles)];
        if (roles.some(role => typeof role !== "string" || !GLOBAL_ROLES.has(role))) {
            return c.json({ error: "Roles must be an array containing only verified, developer or contributor" }, 400);
        }

        const rows = await sql<{ username: string; display_name: string | null; global_roles: string[] }[]>`
            update users
            set global_roles = ${roles as string[]},
                updated_at = now()
            where username = ${username}
            returning username, display_name, global_roles
        `;

        const row = rows[0];
        if (!row) return c.json({ error: "User not found" }, 404);

        c.header("Cache-Control", "no-store");
        return c.json({ user: row });
    } catch (error) {
        console.error("Global role update failed:", error);
        return c.json({ error: "Could not update global roles" }, 500);
    }
});

export default app;
