import type { Context } from "hono";
import { Hono } from "hono";
import { SERVER_ORIGIN } from "../../config/server.ts";
import { sql } from "../../db/client.ts";
import { signMessage } from "../../services/fedi-crypto.ts";

const app = new Hono();

const COOKIE = "__Host-hymenia_session";
const MAX_BODY_SIZE = 16 * 1024;

interface PublicUser {
    id: string;
    username: string;
    email: string;
}

interface ActorRow {
    id: string;
    actor_uri: string;
}

interface AuthUser {
    user: PublicUser;
    actor: ActorRow;
}

interface SpaceRow {
    id: string;
    federation_uri: string;
    origin_host: string;
    owner_actor_id: string;
    name: string;
    description: string | null;
    visibility: string;
    revision: string | number;
    created_at: string | Date;
    updated_at: string | Date;
}

interface SpaceBody {
    name?: unknown;
    description?: unknown;
    visibility?: unknown;
}

function canonicalize(value: unknown): string {
    if (value === null || typeof value !== "object") {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return "[" + value.map(canonicalize).join(",") + "]";
    }

    const entries = Object.entries(value as Record<string, unknown>)
        .filter(([, v]) => v !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, v]) => JSON.stringify(k) + ":" + canonicalize(v));

    return "{" + entries.join(",") + "}";
}

class ForbiddenError extends Error {
    constructor(message = "Forbidden") {
        super(message);
        this.name = "ForbiddenError";
    }
}

function toSpaceDto(row: SpaceRow) {
    return {
        id: row.id,
        federationUri: row.federation_uri,
        originHost: row.origin_host,
        ownerActorId: row.owner_actor_id,
        name: row.name,
        description: row.description,
        visibility: row.visibility,
        revision: Number(row.revision),
        createdAt: new Date(row.created_at).toISOString(),
        updatedAt: new Date(row.updated_at).toISOString(),
    };
}

function readToken(c: Context): string | null {
    const cookie = c.req.header("Cookie") ?? "";
    const prefix = COOKIE + "=";

    const item = cookie
        .split(";")
        .map(v => v.trim())
        .find(v => v.startsWith(prefix));

    const token = item?.slice(prefix.length);
    return token && /^[0-9a-f]{64}$/.test(token) ? token : null;
}

async function hash(value: string): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
    return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}

async function getAuthUser(c: Context): Promise<AuthUser | null> {
    const token = readToken(c);
    if (!token) return null;

    const tokenHash = await hash(token);

    const users = await sql<PublicUser[]>`
        SELECT u.id, u.username, u.email
        FROM public.sessions s
        JOIN public.users u ON u.id = s.user_id
        WHERE s.token_hash = ${tokenHash}
          AND s.expires_at > NOW()
        LIMIT 1
    `;

    const user = users[0];
    if (!user) return null;

    const actors = await sql<ActorRow[]>`
        SELECT id, actor_uri
        FROM "v2".actors
        WHERE local_user_id = ${user.id}
          AND is_active = TRUE
        LIMIT 1
    `;

    const actor = actors[0];
    if (!actor) return null;

    return { user, actor };
}

function isValidUuid(value: string): boolean {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function isValidName(value: unknown): value is string {
    return typeof value === "string" && value.trim().length >= 1 && value.trim().length <= 100;
}

function isValidDescription(value: unknown): value is string | null {
    return value === null || (typeof value === "string" && value.length <= 2000);
}

function isValidVisibility(value: unknown): value is string {
    return value === "public" || value === "private";
}

async function readBody(c: Context): Promise<SpaceBody | null> {
    const raw = await c.req.text();

    if (new TextEncoder().encode(raw).length > MAX_BODY_SIZE) {
        return null;
    }

    try {
        const body: unknown = JSON.parse(raw);
        if (typeof body !== "object" || body === null || Array.isArray(body)) {
            return null;
        }
        return body as SpaceBody;
    } catch {
        return null;
    }
}

async function createSignedEvent(
    eventType: string,
    eventId: string,
    objectUri: string,
    actorUri: string,
    payload: Record<string, unknown>,
): Promise<Record<string, unknown>> {
    const event = {
        id: eventId,
        type: eventType,
        origin: SERVER_ORIGIN,
        actor: actorUri,
        object: objectUri,
        timestamp: new Date().toISOString(),
        payload,
    };

    const signature = await signMessage(canonicalize(event));

    return {
        ...event,
        signature,
    };
}

async function getSpace(spaceId: string): Promise<SpaceRow | null> {
    const rows = await sql<SpaceRow[]>`
        SELECT
            id,
            federation_uri,
            origin_host,
            owner_actor_id,
            name,
            description,
            visibility,
            revision,
            created_at,
            updated_at
        FROM "v2".spaces
        WHERE id = ${spaceId}::uuid
          AND is_deleted = FALSE
        LIMIT 1
    `;
    return rows[0] ?? null;
}

async function isMember(spaceId: string, actorId: string): Promise<boolean> {
    const rows = await sql`
        SELECT 1
        FROM "v2".space_members
        WHERE space_id = ${spaceId}::uuid
          AND actor_id = ${actorId}::uuid
          AND membership_status = 'active'
        LIMIT 1
    `;
    return rows.length > 0;
}

// POST /v2/spaces
app.post("/", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) {
            return c.json({ error: "Not authenticated" }, 401);
        }

        const body = await readBody(c);
        if (!body) {
            return c.json({ error: "Invalid request body" }, 400);
        }

        const name = typeof body.name === "string" ? body.name.trim() : "";
        const description = body.description === undefined ? null : body.description;
        const visibility = body.visibility ?? "private";

        if (!isValidName(name) || !isValidDescription(description) || !isValidVisibility(visibility)) {
            return c.json({ error: "Invalid space details" }, 400);
        }

        const spaceId = crypto.randomUUID();
        const roleId = crypto.randomUUID();
        const eventId = crypto.randomUUID();

        const federationUri = SERVER_ORIGIN + "/spaces/" + spaceId;
        const originHost = new URL(SERVER_ORIGIN).host.toLowerCase();

        const space = await sql.begin(async tx => {
            const rows = await tx<SpaceRow[]>`
                INSERT INTO "v2".spaces (
                    id, federation_uri, origin_host, owner_actor_id,
                    name, description, visibility, revision
                )
                VALUES (
                    ${spaceId}::uuid,
                    ${federationUri},
                    ${originHost},
                    ${auth.actor.id}::uuid,
                    ${name},
                    ${description},
                    ${visibility},
                    1
                )
                RETURNING *
            `;

            const created = rows[0];
            if (!created) throw new Error("Space creation failed");

            await tx`
                INSERT INTO "v2".space_roles (id, space_id, name, is_default, position)
                VALUES (${roleId}::uuid, ${spaceId}::uuid, 'member', TRUE, 0)
            `;

            await tx`
                INSERT INTO "v2".space_members (space_id, actor_id, membership_status)
                VALUES (${spaceId}::uuid, ${auth.actor.id}::uuid, 'active')
            `;

            await tx`
                INSERT INTO "v2".space_member_roles (
                    space_id, actor_id, role_id, assigned_by_actor_id
                )
                VALUES (
                    ${spaceId}::uuid,
                    ${auth.actor.id}::uuid,
                    ${roleId}::uuid,
                    ${auth.actor.id}::uuid
                )
            `;

            const signedEvent = await createSignedEvent("space.created", eventId, federationUri, auth.actor.actor_uri, {
                space_id: spaceId,
                name,
                description,
                visibility,
                owner: auth.actor.actor_uri,
                revision: 1,
            });

            await tx`
                INSERT INTO "v2".federation_outbox (
                    event_id, event_type, object_uri, actor_uri, payload
                )
                VALUES (
                    ${eventId}::uuid,
                    'space.created',
                    ${federationUri},
                    ${auth.actor.actor_uri},
                    ${JSON.stringify(signedEvent)}::jsonb
                )
            `;

            return created;
        });

        c.header("Cache-Control", "no-store");
        return c.json({ space: toSpaceDto(space) }, 201);
    } catch (error) {
        console.error("Space creation failed:", error);
        return c.json({ error: "Space creation failed" }, 500);
    }
});

// GET /v2/spaces
app.get("/", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) {
            return c.json({ error: "Not authenticated" }, 401);
        }

        const spaces = await sql<SpaceRow[]>`
            SELECT
                s.id, s.federation_uri, s.origin_host, s.owner_actor_id,
                s.name, s.description, s.visibility, s.revision,
                s.created_at, s.updated_at
            FROM "v2".spaces s
            JOIN "v2".space_members m ON m.space_id = s.id
            WHERE m.actor_id = ${auth.actor.id}::uuid
              AND m.membership_status = 'active'
              AND s.is_deleted = FALSE
            ORDER BY s.created_at DESC
        `;

        c.header("Cache-Control", "no-store");
        return c.json({ spaces: spaces.map(toSpaceDto) });
    } catch (error) {
        console.error("Space list failed:", error);
        return c.json({ error: "Could not load spaces" }, 500);
    }
});

// GET /v2/spaces/:spaceId
app.get("/:spaceId", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) {
            return c.json({ error: "Not authenticated" }, 401);
        }

        const spaceId = c.req.param("spaceId");
        if (!isValidUuid(spaceId)) {
            return c.json({ error: "Invalid space id" }, 400);
        }

        const space = await getSpace(spaceId);
        if (!space) {
            return c.json({ error: "Space not found" }, 404);
        }

        if (!(await isMember(spaceId, auth.actor.id))) {
            return c.json({ error: "Space not found" }, 404);
        }

        c.header("Cache-Control", "no-store");
        return c.json({ space: toSpaceDto(space) });
    } catch (error) {
        console.error("Space lookup failed:", error);
        return c.json({ error: "Could not load space" }, 500);
    }
});

// PATCH /v2/spaces/:spaceId
app.patch("/:spaceId", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) {
            return c.json({ error: "Not authenticated" }, 401);
        }

        const spaceId = c.req.param("spaceId");
        if (!isValidUuid(spaceId)) {
            return c.json({ error: "Invalid space id" }, 400);
        }

        const body = await readBody(c);
        if (!body) {
            return c.json({ error: "Invalid request body" }, 400);
        }

        if (body.name === undefined && body.description === undefined && body.visibility === undefined) {
            return c.json({ error: "No changes provided" }, 400);
        }

        if (body.name !== undefined && !isValidName(body.name)) {
            return c.json({ error: "Invalid space name" }, 400);
        }
        if (body.description !== undefined && !isValidDescription(body.description)) {
            return c.json({ error: "Invalid description" }, 400);
        }
        if (body.visibility !== undefined && !isValidVisibility(body.visibility)) {
            return c.json({ error: "Invalid visibility" }, 400);
        }

        const eventId = crypto.randomUUID();

        const space = await sql.begin(async tx => {
            const rows = await tx<SpaceRow[]>`
                SELECT *
                FROM "v2".spaces
                WHERE id = ${spaceId}::uuid
                  AND is_deleted = FALSE
                FOR UPDATE
            `;

            const current = rows[0];
            if (!current) return null;

            const member = await tx`
                SELECT 1
                FROM "v2".space_members
                WHERE space_id = ${spaceId}::uuid
                  AND actor_id = ${auth.actor.id}::uuid
                  AND membership_status = 'active'
            `;
            if (member.length === 0) return null;

            if (current.owner_actor_id !== auth.actor.id) {
                throw new ForbiddenError("Only the owner can update this space");
            }

            const name = body.name === undefined ? current.name : (body.name as string).trim();
            const description =
                body.description === undefined ? current.description : (body.description as string | null);
            const visibility = body.visibility === undefined ? current.visibility : (body.visibility as string);

            const updatedRows = await tx<SpaceRow[]>`
                UPDATE "v2".spaces
                SET
                    name = ${name},
                    description = ${description},
                    visibility = ${visibility},
                    revision = revision + 1,
                    updated_at = NOW()
                WHERE id = ${spaceId}::uuid
                RETURNING *
            `;

            const updated = updatedRows[0];
            if (!updated) throw new Error("Space update failed");

            const signedEvent = await createSignedEvent(
                "space.updated",
                eventId,
                updated.federation_uri,
                auth.actor.actor_uri,
                {
                    space_id: spaceId,
                    name,
                    description,
                    visibility,
                    revision: Number(updated.revision),
                },
            );

            await tx`
                INSERT INTO "v2".federation_outbox (
                    event_id, event_type, object_uri, actor_uri, payload
                )
                VALUES (
                    ${eventId}::uuid,
                    'space.updated',
                    ${updated.federation_uri},
                    ${auth.actor.actor_uri},
                    ${JSON.stringify(signedEvent)}::jsonb
                )
            `;

            return updated;
        });

        if (!space) {
            return c.json({ error: "Space not found" }, 404);
        }

        c.header("Cache-Control", "no-store");
        return c.json({ space: toSpaceDto(space) });
    } catch (error) {
        if (error instanceof ForbiddenError) {
            return c.json({ error: error.message }, 403);
        }
        console.error("Space update failed:", error);
        return c.json({ error: "Space update failed" }, 500);
    }
});

// DELETE /v2/spaces/:spaceId
app.delete("/:spaceId", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) {
            return c.json({ error: "Not authenticated" }, 401);
        }

        const spaceId = c.req.param("spaceId");
        if (!isValidUuid(spaceId)) {
            return c.json({ error: "Invalid space id" }, 400);
        }

        const eventId = crypto.randomUUID();

        const deleted = await sql.begin(async tx => {
            const rows = await tx<SpaceRow[]>`
                SELECT *
                FROM "v2".spaces
                WHERE id = ${spaceId}::uuid
                  AND is_deleted = FALSE
                FOR UPDATE
            `;

            const space = rows[0];
            if (!space) return null;

            const member = await tx`
                SELECT 1
                FROM "v2".space_members
                WHERE space_id = ${spaceId}::uuid
                  AND actor_id = ${auth.actor.id}::uuid
                  AND membership_status = 'active'
            `;
            if (member.length === 0) return null;

            if (space.owner_actor_id !== auth.actor.id) {
                throw new ForbiddenError("Only the owner can delete this space");
            }

            const updatedRows = await tx<SpaceRow[]>`
                UPDATE "v2".spaces
                SET
                    is_deleted = TRUE,
                    revision = revision + 1,
                    updated_at = NOW()
                WHERE id = ${spaceId}::uuid
                RETURNING *
            `;

            const updated = updatedRows[0];
            if (!updated) throw new Error("Space deletion failed");

            const signedEvent = await createSignedEvent(
                "space.deleted",
                eventId,
                space.federation_uri,
                auth.actor.actor_uri,
                {
                    space_id: spaceId,
                    revision: Number(updated.revision),
                },
            );

            await tx`
                INSERT INTO "v2".federation_outbox (
                    event_id, event_type, object_uri, actor_uri, payload
                )
                VALUES (
                    ${eventId}::uuid,
                    'space.deleted',
                    ${space.federation_uri},
                    ${auth.actor.actor_uri},
                    ${JSON.stringify(signedEvent)}::jsonb
                )
            `;

            return true;
        });

        if (!deleted) {
            return c.json({ error: "Space not found" }, 404);
        }

        c.header("Cache-Control", "no-store");
        return c.json({ success: true });
    } catch (error) {
        if (error instanceof ForbiddenError) {
            return c.json({ error: error.message }, 403);
        }
        console.error("Space deletion failed:", error);
        return c.json({ error: "Space deletion failed" }, 500);
    }
});

export default app;
