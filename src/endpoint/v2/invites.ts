import type { Context } from "hono";
import { Hono } from "hono";
import { SERVER_ORIGIN } from "../../config/server.ts";
import { sql } from "../../db/client.ts";
import { getAuthUser } from "../../services/auth.ts";
import { enqueueOutbox } from "../../services/federation.ts";
import { acceptInvite, generateInviteCode, hashInviteCode } from "../../services/invites.ts";
import { hasPermission, PERMISSIONS } from "../../services/permissions.ts";

const app = new Hono();

const MAX_BODY_SIZE = 16 * 1024;

function isValidUuid(value: string): boolean {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

async function readBody(c: Context): Promise<Record<string, unknown> | null> {
    const raw = await c.req.text();

    if (new TextEncoder().encode(raw).length > MAX_BODY_SIZE) {
        return null;
    }

    try {
        const body: unknown = JSON.parse(raw);
        if (typeof body !== "object" || body === null || Array.isArray(body)) {
            return null;
        }
        return body as Record<string, unknown>;
    } catch {
        return null;
    }
}

async function isSpaceMember(spaceId: string, actorId: string): Promise<boolean> {
    const rows = await sql`
        SELECT 1 FROM "v2".space_members
        WHERE space_id = ${spaceId}::uuid
          AND actor_id = ${actorId}::uuid
          AND membership_status = 'active'
        LIMIT 1
    `;
    return rows.length > 0;
}

// POST /v2/invites
app.post("/", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        const body = await readBody(c);
        if (!body) return c.json({ error: "Invalid request body" }, 400);

        const spaceId = typeof body.spaceId === "string" ? body.spaceId : "";
        if (!isValidUuid(spaceId)) return c.json({ error: "Invalid space id" }, 400);

        if (!(await isSpaceMember(spaceId, auth.actor.id))) {
            return c.json({ error: "Space not found" }, 404);
        }

        if (!(await hasPermission(spaceId, auth.actor.id, PERMISSIONS.invitesCreate))) {
            return c.json({ error: "Not allowed" }, 403);
        }

        const maxUses = body.maxUses === undefined || body.maxUses === null ? null : Number(body.maxUses);

        if (maxUses !== null && (!Number.isInteger(maxUses) || maxUses < 1 || maxUses > 1000)) {
            return c.json({ error: "Invalid maxUses" }, 400);
        }

        let expiresAt: Date | null = null;

        if (body.expiresAt !== undefined && body.expiresAt !== null) {
            if (typeof body.expiresAt !== "string") {
                return c.json({ error: "Invalid expiresAt" }, 400);
            }

            const parsed = new Date(body.expiresAt);

            if (Number.isNaN(parsed.getTime()) || parsed.getTime() <= Date.now()) {
                return c.json({ error: "Invalid expiresAt" }, 400);
            }

            expiresAt = parsed;
        }

        let roleId: string | null = null;

        if (body.roleId !== undefined && body.roleId !== null) {
            if (typeof body.roleId !== "string" || !isValidUuid(body.roleId)) {
                return c.json({ error: "Invalid roleId" }, 400);
            }

            const roles = await sql`
                SELECT 1 FROM "v2".space_roles
                WHERE space_id = ${spaceId}::uuid AND id = ${body.roleId}::uuid
                LIMIT 1
            `;

            if (roles.length !== 1) {
                return c.json({ error: "Invalid roleId" }, 400);
            }

            roleId = body.roleId;
        }

        const code = generateInviteCode();
        const codeHash = await hashInviteCode(code);

        const rows = await sql<{ id: string; created_at: string | Date }[]>`
            INSERT INTO "v2".space_invites (
                space_id, code_hash, role_id, created_by_actor_id, max_uses, expires_at
            )
            VALUES (
                ${spaceId}::uuid,
                ${codeHash},
                ${roleId}::uuid,
                ${auth.actor.id}::uuid,
                ${maxUses},
                ${expiresAt}
            )
            RETURNING id, created_at
        `;

        const invite = rows[0];
        if (!invite) throw new Error("Invite insert failed");

        await enqueueOutbox("invite.created", `${SERVER_ORIGIN}/invites/${invite.id}`, auth.actor.actor_uri, {
            space_id: spaceId,
            invite_id: invite.id,
        });

        c.header("Cache-Control", "no-store");

        // the plaintext code is returned once and never stored
        return c.json(
            {
                invite: {
                    id: invite.id,
                    spaceId,
                    code,
                    maxUses,
                    usesCount: 0,
                    expiresAt: expiresAt ? expiresAt.toISOString() : null,
                    createdAt: new Date(invite.created_at).toISOString(),
                },
            },
            201,
        );
    } catch (error) {
        console.error("Invite create failed:", error);
        return c.json({ error: "Invite create failed" }, 500);
    }
});

// GET /v2/invites?spaceId=...
app.get("/", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        const spaceId = c.req.query("spaceId") ?? "";
        if (!isValidUuid(spaceId)) return c.json({ error: "Invalid space id" }, 400);

        if (!(await isSpaceMember(spaceId, auth.actor.id))) {
            return c.json({ error: "Space not found" }, 404);
        }

        const rows = await sql<
            {
                id: string;
                max_uses: number | null;
                uses_count: number;
                expires_at: string | Date | null;
                revoked_at: string | Date | null;
                created_at: string | Date;
            }[]
        >`
            SELECT id, max_uses, uses_count, expires_at, revoked_at, created_at
            FROM "v2".space_invites
            WHERE space_id = ${spaceId}::uuid
            ORDER BY created_at DESC
        `;

        c.header("Cache-Control", "no-store");

        return c.json({
            invites: rows.map(row => ({
                id: row.id,
                spaceId,
                maxUses: row.max_uses,
                usesCount: row.uses_count,
                expiresAt: row.expires_at ? new Date(row.expires_at).toISOString() : null,
                revokedAt: row.revoked_at ? new Date(row.revoked_at).toISOString() : null,
                createdAt: new Date(row.created_at).toISOString(),
            })),
        });
    } catch (error) {
        console.error("Invite list failed:", error);
        return c.json({ error: "Invite list failed" }, 500);
    }
});

// DELETE /v2/invites/:inviteId
app.delete("/:inviteId", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        const inviteId = c.req.param("inviteId");
        if (!isValidUuid(inviteId)) return c.json({ error: "Invalid invite id" }, 400);

        const found = await sql<{ space_id: string }[]>`
            SELECT space_id FROM "v2".space_invites
            WHERE id = ${inviteId}::uuid
            LIMIT 1
        `;

        const invite = found[0];
        if (!invite) return c.json({ error: "Invite not found" }, 404);

        if (!(await isSpaceMember(invite.space_id, auth.actor.id))) {
            return c.json({ error: "Invite not found" }, 404);
        }

        if (!(await hasPermission(invite.space_id, auth.actor.id, PERMISSIONS.invitesManage))) {
            return c.json({ error: "Not allowed" }, 403);
        }

        const rows = await sql<{ id: string }[]>`
            UPDATE "v2".space_invites
            SET revoked_at = now()
            WHERE id = ${inviteId}::uuid AND revoked_at IS NULL
            RETURNING id
        `;

        if (rows.length !== 1) return c.json({ error: "Invite not found" }, 404);

        c.header("Cache-Control", "no-store");
        return c.json({ success: true });
    } catch (error) {
        console.error("Invite revoke failed:", error);
        return c.json({ error: "Invite revoke failed" }, 500);
    }
});

// POST /v2/invites/:code/accept
app.post("/:code/accept", async c => {
    try {
        const auth = await getAuthUser(c);
        if (!auth) return c.json({ error: "Not authenticated" }, 401);

        const result = await acceptInvite(c.req.param("code"), auth.actor.id);

        if (!result.ok) {
            return c.json({ error: result.error }, result.status as 400);
        }

        if (!result.alreadyMember) {
            await enqueueOutbox(
                "space.member.joined",
                `${SERVER_ORIGIN}/spaces/${result.spaceId}`,
                auth.actor.actor_uri,
                { space_id: result.spaceId, actor_uri: auth.actor.actor_uri },
            );
        }

        c.header("Cache-Control", "no-store");
        return c.json({ success: true, spaceId: result.spaceId, alreadyMember: result.alreadyMember });
    } catch (error) {
        console.error("Invite accept failed:", error);
        return c.json({ error: "Invite accept failed" }, 500);
    }
});

export default app;
