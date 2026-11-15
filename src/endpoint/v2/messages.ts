import { Hono } from "hono";
import { sql } from "../../db/client.ts";
import { getAuthUser } from "../../services/auth.ts";
import { sendToActors } from "../../services/hub.ts";

const app = new Hono();

interface MessageRow {
    id: string;
    channel_id: string;
    author_actor_id: string;
    content: string;
    created_at: string | Date;
}

function isValidUuid(value: string): boolean {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function toMessageDto(row: MessageRow) {
    return {
        id: row.id,
        chatId: row.channel_id,
        authorActorId: row.author_actor_id,
        content: row.content,
        createdAt: new Date(row.created_at).toISOString(),
    };
}

async function getChatSpace(chatId: string): Promise<string | null> {
    const rows = await sql<{ space_id: string }[]>`
        select space_id from "v2".channels
        where id = ${chatId}::uuid and is_archived = false
        limit 1
    `;
    return rows[0]?.space_id ?? null;
}

async function isSpaceMember(spaceId: string, actorId: string): Promise<boolean> {
    const rows = await sql`
        select 1 from "v2".space_members
        where space_id = ${spaceId}::uuid
          and actor_id = ${actorId}::uuid
          and membership_status = 'active'
        limit 1
    `;
    return rows.length > 0;
}

// POST /v2/messages/chats/:chatId
app.post("/chats/:chatId", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        const chatId = c.req.param("chatId");
        if (!isValidUuid(chatId)) return c.json({ error: "Invalid chat id" }, 400);

        const spaceId = await getChatSpace(chatId);
        if (!spaceId || !(await isSpaceMember(spaceId, auth.actor.id))) {
            return c.json({ error: "Chat not found" }, 404);
        }

        let body: unknown;
        try {
            body = await c.req.json();
        } catch {
            return c.json({ error: "Invalid request body" }, 400);
        }

        const content =
            typeof (body as { content?: unknown })?.content === "string"
                ? (body as { content: string }).content.trim()
                : "";
        if (content.length < 1 || content.length > 4000) {
            return c.json({ error: "Invalid content" }, 400);
        }

        const rows = await sql<MessageRow[]>`
            insert into "v2".messages (id, channel_id, author_actor_id, content)
            values (${crypto.randomUUID()}::uuid, ${chatId}::uuid, ${auth.actor.id}::uuid, ${content})
            returning id, channel_id, author_actor_id, content, created_at
        `;
        const message = rows[0];
        if (!message) throw new Error("Message insert failed");

        const dto = toMessageDto(message);

        const members = await sql<{ actor_id: string }[]>`
            select actor_id from "v2".space_members
            where space_id = ${spaceId}::uuid and membership_status = 'active'
        `;
        sendToActors(
            members.map(m => m.actor_id),
            "message.created",
            dto,
        );

        c.header("Cache-Control", "no-store");
        return c.json({ message: dto }, 201);
    } catch (error) {
        console.error("Message send failed:", error);
        return c.json({ error: "Message send failed" }, 500);
    }
});

// GET /v2/messages/chats/:chatId?before=<iso timestamp>&limit=50
app.get("/chats/:chatId", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        const chatId = c.req.param("chatId");
        if (!isValidUuid(chatId)) return c.json({ error: "Invalid chat id" }, 400);

        const spaceId = await getChatSpace(chatId);
        if (!spaceId || !(await isSpaceMember(spaceId, auth.actor.id))) {
            return c.json({ error: "Chat not found" }, 404);
        }

        const limit = Math.min(Math.max(Number(c.req.query("limit") ?? 50) || 50, 1), 100);
        const beforeRaw = c.req.query("before");
        const before = beforeRaw && !Number.isNaN(Date.parse(beforeRaw)) ? new Date(beforeRaw) : null;

        const rows = await sql<MessageRow[]>`
            select id, channel_id, author_actor_id, content, created_at
            from "v2".messages
            where channel_id = ${chatId}::uuid
              and deleted_at is null
              and (${before}::timestamptz is null or created_at < ${before}::timestamptz)
            order by created_at desc, id desc
            limit ${limit}
        `;

        c.header("Cache-Control", "no-store");
        return c.json({ messages: rows.map(toMessageDto) });
    } catch (error) {
        console.error("Message list failed:", error);
        return c.json({ error: "Couldn't load messages" }, 500);
    }
});

export default app;
