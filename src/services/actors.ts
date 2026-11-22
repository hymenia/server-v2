import { sql } from "../db/client.ts";

export interface ActorRef {
    id: string;
    actor_uri: string;
}

// remote actors are created on first contact
// the actor uri carries the host and username, so no fetch is needed yet

export async function ensureRemoteActor(actorUri: string): Promise<ActorRef | null> {
    let parsed: URL;

    try {
        parsed = new URL(actorUri);
    } catch {
        return null;
    }

    if (parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "") {
        return null;
    }

    if (parsed.search !== "" || parsed.hash !== "") {
        return null;
    }

    const match = /^\/actors\/([a-z0-9_]+(?:\.[a-z0-9_]+)*)$/.exec(parsed.pathname);

    if (!match) {
        return null;
    }

    const username = match[1];
    const host = parsed.host.toLowerCase();

    if (username.length < 3 || username.length > 30) {
        return null;
    }

    const rows = await sql<ActorRef[]>`
        INSERT INTO "v2".actors (actor_uri, host, username, local_user_id)
        VALUES (${parsed.origin + parsed.pathname}, ${host}, ${username}, NULL)
        ON CONFLICT (actor_uri) DO NOTHING
        RETURNING id, actor_uri
    `;

    if (rows[0]) {
        return rows[0];
    }

    const existing = await sql<ActorRef[]>`
        SELECT id, actor_uri
        FROM "v2".actors
        WHERE actor_uri = ${parsed.origin + parsed.pathname}
        LIMIT 1
    `;

    return existing[0] ?? null;
}
