import { SERVER_DOMAIN, SERVER_ORIGIN } from "../config/server.ts";
import { sql } from "./client.ts";

// create actor rows for local users that do not have one yet
// registration does this inline now, so this only covers older accounts (aka none 😂)

try {
    const users = await sql<{ id: string; username: string }[]>`
        select u.id, u.username
        from public.users u
        left join "v2".actors a on a.local_user_id = u.id
        where a.id is null
        order by u.created_at asc
    `;

    let created = 0;
    let skipped = 0;

    for (const user of users) {
        const rows = await sql`
            insert into "v2".actors (actor_uri, host, username, local_user_id)
            values (
                ${SERVER_ORIGIN + "/actors/" + user.username},
                ${SERVER_DOMAIN.toLowerCase()},
                ${user.username},
                ${user.id}::uuid
            )
            on conflict (actor_uri) do nothing
            returning id
        `;

        if (rows.length === 1) {
            created += 1;
        } else {
            skipped += 1;
            console.error(`skipped ${user.username}: actor uri already taken`);
        }
    }

    console.log(`backfilled ${created} of ${users.length} users, skipped ${skipped}`);
} finally {
    await sql.end();
}
