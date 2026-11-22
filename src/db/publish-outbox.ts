import { signEnvelope } from "../services/federation.ts";
import { sql } from "./client.ts";

interface OutboxRow {
    id: string;
    event_id: string;
    event_type: string;
    object_uri: string;
    actor_uri: string;
    payload: Record<string, unknown>;
    attempts: number;
}

try {
    const rows = await sql<OutboxRow[]>`
        SELECT id, event_id, event_type, object_uri, actor_uri, payload, attempts
        FROM "v2".federation_outbox
        WHERE published_at IS NULL
          AND attempts < ${10}
        ORDER BY created_at ASC
        LIMIT ${50}
    `;

    let published = 0;
    let failed = 0;

    for (const row of rows) {
        let target: string;

        try {
            target = new URL(row.actor_uri).origin;
        } catch {
            await sql`
                UPDATE "v2".federation_outbox
                SET attempts = attempts + 1, last_error = ${"invalid actor uri"}
                WHERE id = ${row.id}::uuid
            `;
            failed += 1;
            continue;
        }

        const envelope = await signEnvelope("hymenia.event", row.event_id, {
            event_type: row.event_type,
            object_uri: row.object_uri,
            actor_uri: row.actor_uri,
            payload: row.payload,
        });

        try {
            const response = await fetch(`${target}/v2/federation/inbox`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-Hymenia-Signature": envelope.signature,
                },
                body: envelope.body,
                signal: AbortSignal.timeout(10000),
            });

            if (!response.ok) {
                throw new Error(`remote responded ${response.status}`);
            }

            await sql`
                UPDATE "v2".federation_outbox
                SET published_at = now(), attempts = attempts + 1, last_error = NULL
                WHERE id = ${row.id}::uuid
            `;
            published += 1;
        } catch (error) {
            await sql`
                UPDATE "v2".federation_outbox
                SET attempts = attempts + 1, last_error = ${String(error).slice(0, 500)}
                WHERE id = ${row.id}::uuid
            `;
            failed += 1;
        }
    }

    console.log(`published ${published}, failed ${failed}, pending ${rows.length - published - failed}`);
} finally {
    await sql.end();
}
