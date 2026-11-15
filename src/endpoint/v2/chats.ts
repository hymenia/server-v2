import type { Context } from "hono";
import { Hono } from "hono";
import { SERVER_ORIGIN } from "../../config/server.ts";
import { sql } from "../../db/client.ts";
import { getAuthUser } from "../../services/auth.ts";
import { signMessage } from "../../services/fedi-crypto.ts";

const app = new Hono();

const MAX_BODY_SIZE = 16 * 1024;

type AccessMode = "inherited" | "restricted" | "public";

interface ChatRow {
    id: string;
    space_id: string;
    parent_id: string | null;
    name: string;
    description: string | null;
    position: number;
    access_mode: string;
    created_by_actor_id: string;
    is_archived: boolean;
    created_at: string | Date;
    updated_at: string | Date;
}

interface ChatBody {
    name?: unknown;
    description?: unknown;
    parentId?: unknown;
    position?: unknown;
    accessMode?: unknown;
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
    constructor(message = "forbidden") {
        super(message);
        this.name = "ForbiddenError";
    }
}

function toChatDto(row: ChatRow) {
    return {
        id: row.id,
        spaceId: row.space_id,
        parentId: row.parent_id,
        name: row.name,
        description: row.description,
        position: row.position,
        accessMode: row.access_mode,
        createdByActorId: row.created_by_actor_id,
        isArchived: row.is_archived,
        createdAt: new Date(row.created_at).toISOString(),
        updatedAt: new Date(row.updated_at).toISOString(),
    };
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

function isValidAccessMode(value: unknown): value is AccessMode {
    return value === "inherited" || value === "restricted" || value === "public";
}

function isValidPosition(value: unknown): value is number {
    return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

async function readBody(c: Context): Promise<ChatBody | null> {
    const raw = await c.req.text();

    if (new TextEncoder().encode(raw).length > MAX_BODY_SIZE) {
        return null;
    }

    try {
        const body: unknown = JSON.parse(raw);
        if (typeof body !== "object" || body === null || Array.isArray(body)) {
            return null;
        }
        return body as ChatBody;
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

async function isSpaceMember(spaceId: string, actorId: string): Promise<boolean> {
    const rows = await sql`
        select 1
        from "v2".space_members
        where space_id = ${spaceId}::uuid
          and actor_id = ${actorId}::uuid
          and membership_status = 'active'
        limit 1
    `;
    return rows.length > 0;
}

async function getChat(chatId: string): Promise<ChatRow | null> {
    const rows = await sql<ChatRow[]>`
        select
            id,
            space_id,
            parent_id,
            name,
            description,
            position,
            access_mode,
            created_by_actor_id,
            is_archived,
            created_at,
            updated_at
        from "v2".channels
        where id = ${chatId}::uuid
          and is_archived = false
        limit 1
    `;
    return rows[0] ?? null;
}

// POST /v2/spaces/:spaceId/chats
app.post("/spaces/:spaceId/chats", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) {
            return c.json({ error: "Not authenticated" }, 401);
        }

        const spaceId = c.req.param("spaceId");
        if (!isValidUuid(spaceId)) {
            return c.json({ error: "Invalid space id" }, 400);
        }

        if (!(await isSpaceMember(spaceId, auth.actor.id))) {
            return c.json({ error: "Space not found" }, 404);
        }

        const body = await readBody(c);
        if (!body) {
            return c.json({ error: "Invalid request body" }, 400);
        }

        const name = typeof body.name === "string" ? body.name.trim() : "";
        const description = body.description === undefined ? null : body.description;
        const position = body.position === undefined ? 0 : body.position;
        const accessMode = body.accessMode === undefined ? "inherited" : body.accessMode;

        if (!isValidName(name)) {
            return c.json({ error: "Invalid chat name" }, 400);
        }
        if (!isValidDescription(description)) {
            return c.json({ error: "Invalid description" }, 400);
        }

        let parentId: string | null = null;
        if (body.parentId !== undefined && body.parentId !== null) {
            if (typeof body.parentId !== "string" || !isValidUuid(body.parentId)) {
                return c.json({ error: "Invalid parent id" }, 400);
            }
            parentId = body.parentId;
        }

        if (!isValidPosition(position)) {
            return c.json({ error: "Invalid position" }, 400);
        }
        if (!isValidAccessMode(accessMode)) {
            return c.json({ error: "Invalid access mode" }, 400);
        }

        const chatId = crypto.randomUUID();
        const eventId = crypto.randomUUID();
        const federationUri = SERVER_ORIGIN + "/chats/" + chatId;

        const chat = await sql.begin(async tx => {
            if (parentId) {
                const parent = await tx`
                    select id
                    from "v2".channels
                    where id = ${parentId}::uuid
                      and space_id = ${spaceId}::uuid
                      and is_archived = false
                    limit 1
                `;
                if (parent.length === 0) {
                    return null;
                }
            }

            const rows = await tx<ChatRow[]>`
                insert into "v2".channels (
                    id,
                    space_id,
                    parent_id,
                    name,
                    description,
                    position,
                    access_mode,
                    created_by_actor_id
                )
                values (
                    ${chatId}::uuid,
                    ${spaceId}::uuid,
                    ${parentId}::uuid,
                    ${name},
                    ${description},
                    ${position},
                    ${accessMode},
                    ${auth.actor.id}::uuid
                )
                returning *
            `;

            const created = rows[0];
            if (!created) throw new Error("Chat creation failed");

            const signedEvent = await createSignedEvent("chat.created", eventId, federationUri, auth.actor.actor_uri, {
                chat_id: chatId,
                space_id: spaceId,
                parent_id: parentId,
                name,
                description,
                position,
                access_mode: accessMode,
                created_by: auth.actor.actor_uri,
            });

            await tx`
                insert into "v2".federation_outbox (
                    event_id, event_type, object_uri, actor_uri, payload
                )
                values (
                    ${eventId}::uuid,
                    'chat.created',
                    ${federationUri},
                    ${auth.actor.actor_uri},
                    ${JSON.stringify(signedEvent)}::jsonb
                )
            `;

            return created;
        });

        if (!chat) {
            return c.json({ error: "Parent chat not found" }, 404);
        }

        c.header("Cache-Control", "no-store");
        return c.json({ chat: toChatDto(chat) }, 201);
    } catch (error) {
        console.error("Chat creation failed:", error);
        return c.json({ error: "Chat creation failed" }, 500);
    }
});

// GET /v2/spaces/:spaceId/chats
app.get("/spaces/:spaceId/chats", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) {
            return c.json({ error: "Not authenticated" }, 401);
        }

        const spaceId = c.req.param("spaceId");
        if (!isValidUuid(spaceId)) {
            return c.json({ error: "Invalid space id" }, 400);
        }

        if (!(await isSpaceMember(spaceId, auth.actor.id))) {
            return c.json({ error: "Space not found" }, 404);
        }

        const chats = await sql<ChatRow[]>`
            select
                id,
                space_id,
                parent_id,
                name,
                description,
                position,
                access_mode,
                created_by_actor_id,
                is_archived,
                created_at,
                updated_at
            from "v2".channels
            where space_id = ${spaceId}::uuid
              and is_archived = false
            order by position asc, created_at asc
        `;

        c.header("Cache-Control", "no-store");
        return c.json({ chats: chats.map(toChatDto) });
    } catch (error) {
        console.error("Chat list failed:", error);
        return c.json({ error: "Couldn't load chats" }, 500);
    }
});

// GET /v2/chats/:chatId
app.get("/chats/:chatId", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) {
            return c.json({ error: "Not authenticated" }, 401);
        }

        const chatId = c.req.param("chatId");
        if (!isValidUuid(chatId)) {
            return c.json({ error: "Invalid chat id" }, 400);
        }

        const chat = await getChat(chatId);
        if (!chat) {
            return c.json({ error: "Chat not found" }, 404);
        }

        if (!(await isSpaceMember(chat.space_id, auth.actor.id))) {
            return c.json({ error: "Chat not found" }, 404);
        }

        c.header("Cache-Control", "no-store");
        return c.json({ chat: toChatDto(chat) });
    } catch (error) {
        console.error("chat lookup failed:", error);
        return c.json({ error: "Could not load chat" }, 500);
    }
});

// PATCH /v2/chats/:chatId
app.patch("/chats/:chatId", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) {
            return c.json({ error: "Not authenticated" }, 401);
        }

        const chatId = c.req.param("chatId");
        if (!isValidUuid(chatId)) {
            return c.json({ error: "Invalid chat id" }, 400);
        }

        const body = await readBody(c);
        if (!body) {
            return c.json({ error: "Invalid request body" }, 400);
        }

        if (
            body.name === undefined &&
            body.description === undefined &&
            body.position === undefined &&
            body.accessMode === undefined
        ) {
            return c.json({ error: "No changes provided" }, 400);
        }

        if (body.name !== undefined && !isValidName(body.name)) {
            return c.json({ error: "Invalid chat name" }, 400);
        }
        if (body.description !== undefined && !isValidDescription(body.description)) {
            return c.json({ error: "Invalid description" }, 400);
        }
        if (body.position !== undefined && !isValidPosition(body.position)) {
            return c.json({ error: "Invalid position" }, 400);
        }
        if (body.accessMode !== undefined && !isValidAccessMode(body.accessMode)) {
            return c.json({ error: "Invalid access mode" }, 400);
        }

        const eventId = crypto.randomUUID();

        const chat = await sql.begin(async tx => {
            const rows = await tx<ChatRow[]>`
                select *
                from "v2".channels
                where id = ${chatId}::uuid
                  and is_archived = false
                for update
            `;

            const current = rows[0];
            if (!current) return null;

            if (!(await isSpaceMember(current.space_id, auth.actor.id))) {
                return null;
            }

            // for now only creator or space owner can edit
            // later replace with real permission check
            //TODO TODO TODO TODO TODO TODO TODO TODO AAAGH

            const space = await tx`
                select owner_actor_id
                from "v2".spaces
                where id = ${current.space_id}::uuid
                limit 1
            `;
            const ownerId = space[0]?.owner_actor_id;

            if (current.created_by_actor_id !== auth.actor.id && ownerId !== auth.actor.id) {
                throw new ForbiddenError("Not allowed to update this chat");
            }

            const name = body.name === undefined ? current.name : (body.name as string).trim();
            const description =
                body.description === undefined ? current.description : (body.description as string | null);
            const position = body.position === undefined ? current.position : (body.position as number);
            const accessMode = body.accessMode === undefined ? current.access_mode : (body.accessMode as string);

            const updatedRows = await tx<ChatRow[]>`
                update "v2".channels
                set
                    name = ${name},
                    description = ${description},
                    position = ${position},
                    access_mode = ${accessMode},
                    updated_at = now()
                where id = ${chatId}::uuid
                returning *
            `;

            const updated = updatedRows[0];
            if (!updated) throw new Error("Chat update failed");

            const federationUri = SERVER_ORIGIN + "/chats/" + chatId;

            const signedEvent = await createSignedEvent("chat.updated", eventId, federationUri, auth.actor.actor_uri, {
                chat_id: chatId,
                space_id: updated.space_id,
                name,
                description,
                position,
                access_mode: accessMode,
            });

            await tx`
                insert into "v2".federation_outbox (
                    event_id, event_type, object_uri, actor_uri, payload
                )
                values (
                    ${eventId}::uuid,
                    'chat.updated',
                    ${federationUri},
                    ${auth.actor.actor_uri},
                    ${JSON.stringify(signedEvent)}::jsonb
                )
            `;

            return updated;
        });

        if (!chat) {
            return c.json({ error: "Chat not found" }, 404);
        }

        c.header("Cache-Control", "no-store");
        return c.json({ chat: toChatDto(chat) });
    } catch (error) {
        if (error instanceof ForbiddenError) {
            return c.json({ error: error.message }, 403);
        }
        console.error("Chat update failed:", error);
        return c.json({ error: "Chat update failed" }, 500);
    }
});

// DELETE /v2/chats/:chatId
app.delete("/chats/:chatId", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) {
            return c.json({ error: "Not authenticated" }, 401);
        }

        const chatId = c.req.param("chatId");
        if (!isValidUuid(chatId)) {
            return c.json({ error: "Invalid chat id" }, 400);
        }

        const eventId = crypto.randomUUID();

        const deleted = await sql.begin(async tx => {
            const rows = await tx<ChatRow[]>`
                select *
                from "v2".channels
                where id = ${chatId}::uuid
                  and is_archived = false
                for update
            `;

            const chat = rows[0];
            if (!chat) return null;

            if (!(await isSpaceMember(chat.space_id, auth.actor.id))) {
                return null;
            }

            const space = await tx`
                select owner_actor_id
                from "v2".spaces
                where id = ${chat.space_id}::uuid
                limit 1
            `;
            const ownerId = space[0]?.owner_actor_id;

            if (chat.created_by_actor_id !== auth.actor.id && ownerId !== auth.actor.id) {
                throw new ForbiddenError("Not allowed to delete this chat");
            }

            await tx`
                update "v2".channels
                set
                    is_archived = true,
                    updated_at = now()
                where id = ${chatId}::uuid
            `;

            const federationUri = SERVER_ORIGIN + "/chats/" + chatId;

            const signedEvent = await createSignedEvent("chat.archived", eventId, federationUri, auth.actor.actor_uri, {
                chat_id: chatId,
                space_id: chat.space_id,
            });

            await tx`
                insert into "v2".federation_outbox (
                    event_id, event_type, object_uri, actor_uri, payload
                )
                values (
                    ${eventId}::uuid,
                    'chat.archived',
                    ${federationUri},
                    ${auth.actor.actor_uri},
                    ${JSON.stringify(signedEvent)}::jsonb
                )
            `;

            return true;
        });

        if (!deleted) {
            return c.json({ error: "Chat not found" }, 404);
        }

        c.header("Cache-Control", "no-store");
        return c.json({ success: true });
    } catch (error) {
        if (error instanceof ForbiddenError) {
            return c.json({ error: error.message }, 403);
        }
        console.error("Chat delete failed:", error);
        return c.json({ error: "Chat delete failed" }, 500);
    }
});

export default app;
