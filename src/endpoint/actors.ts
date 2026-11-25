import { Hono } from "hono";
import { SERVER_DOMAIN, SERVER_ORIGIN } from "../config/server.ts";
import { sql } from "../db/client.ts";

const app = new Hono();

interface ActorDocRow {
    id: string;
    username: string;
    display_name: string | null;
    bio: string | null;
    avatar_url: string | null;
    is_bot: boolean;
    is_active: boolean;
    created_at: string | Date;
}

function isValidUsername(username: string): boolean {
    return /^[a-z0-9_]+(?:\.[a-z0-9_]+)*$/.test(username) && username.length >= 3 && username.length <= 30;
}

// GET /actors/:username
// the actor document peers fetch, the uri matches v2.actors.actor_uri
app.get("/:username", async c => {
    const username = c.req.param("username").trim().toLowerCase();

    if (!isValidUsername(username)) {
        return c.json({ error: "Invalid username" }, 400);
    }

    try {
        const rows = await sql<ActorDocRow[]>`
            SELECT
                a.id,
                a.username,
                u.display_name,
                u.bio,
                u.avatar_url,
                u.is_bot,
                a.is_active,
                a.created_at
            FROM "v2".actors a
            LEFT JOIN users u ON u.id = a.local_user_id
            WHERE a.host = ${SERVER_DOMAIN}
              AND a.username = ${username}
            LIMIT 1
        `;

        const actor = rows[0];

        if (!actor) {
            return c.json({ error: "Actor not found" }, 404);
        }

        if (!actor.is_active) {
            c.header("Cache-Control", "public, max-age=60");
            return c.json({ error: "Actor is inactive", isActive: false }, 410);
        }

        c.header("Cache-Control", "public, max-age=60");

        return c.json({
            actor: {
                id: actor.id,
                uri: `${SERVER_ORIGIN}/actors/${actor.username}`,
                username: actor.username,
                host: SERVER_DOMAIN,
                address: `${actor.username}@${SERVER_DOMAIN}`,
                displayName: actor.display_name,
                bio: actor.bio,
                avatar: `${SERVER_ORIGIN}/v2/avatar/${actor.username}`,
                type: actor.is_bot ? "bot" : "user",
                isActive: true,
                createdAt: new Date(actor.created_at).toISOString(),
            },
        });
    } catch (error) {
        console.error("Actor document failed:", error);
        return c.json({ error: "Actor document temporarily unavailable" }, 500);
    }
});

export default app;
