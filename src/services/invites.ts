import { sql } from "../db/client.ts";

export type AcceptResult =
    | { ok: true; spaceId: string; alreadyMember: boolean }
    | { ok: false; status: number; error: string };

async function sha256Hex(value: string): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
    return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}

export function generateInviteCode(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export async function hashInviteCode(code: string): Promise<string> {
    return await sha256Hex(code);
}

// takes an actor id so a signed federation accept can reuse it
export async function acceptInvite(code: string, actorId: string): Promise<AcceptResult> {
    if (!/^[A-Za-z0-9_-]{43}$/.test(code)) {
        return { ok: false, status: 400, error: "Invalid invite code" };
    }

    const codeHash = await hashInviteCode(code);

    return await sql.begin(async tx => {
        const invites = await tx<{
            id: string;
            space_id: string;
            max_uses: number | null;
            uses_count: number;
            expires_at: string | Date | null;
            revoked_at: string | Date | null;
        }[]>`
            SELECT id, space_id, max_uses, uses_count, expires_at, revoked_at
            FROM "v2".space_invites
            WHERE code_hash = ${codeHash}
            FOR UPDATE
        `;

        const invite = invites[0];

        if (!invite) {
            return { ok: false, status: 404, error: "Invite not found" } as AcceptResult;
        }

        if (invite.revoked_at !== null) {
            return { ok: false, status: 410, error: "Invite revoked" } as AcceptResult;
        }

        if (invite.expires_at !== null && new Date(invite.expires_at).getTime() <= Date.now()) {
            return { ok: false, status: 410, error: "Invite expired" } as AcceptResult;
        }

        if (invite.max_uses !== null && invite.uses_count >= invite.max_uses) {
            return { ok: false, status: 409, error: "Invite already used up" } as AcceptResult;
        }

        const used = await tx<{ invite_id: string }[]>`
            INSERT INTO "v2".space_invite_uses (invite_id, actor_id)
            VALUES (${invite.id}::uuid, ${actorId}::uuid)
            ON CONFLICT (invite_id, actor_id) DO NOTHING
            RETURNING invite_id
        `;

        const alreadyMember = used.length !== 1;

        if (!alreadyMember) {
            await tx`
                UPDATE "v2".space_invites
                SET uses_count = uses_count + 1
                WHERE id = ${invite.id}::uuid
            `;
        }

        await tx`
            INSERT INTO "v2".space_members (space_id, actor_id, membership_status)
            VALUES (${invite.space_id}::uuid, ${actorId}::uuid, 'active')
            ON CONFLICT (space_id, actor_id) DO NOTHING
        `;

        // new members get the space default role so they hold its permissions
        await tx`
            INSERT INTO "v2".space_member_roles (space_id, actor_id, role_id)
            SELECT ${invite.space_id}::uuid, ${actorId}::uuid, r.id
            FROM "v2".space_roles r
            WHERE r.space_id = ${invite.space_id}::uuid
              AND r.is_default = TRUE
            ON CONFLICT (space_id, actor_id, role_id) DO NOTHING
        `;

        return { ok: true, spaceId: invite.space_id, alreadyMember } as AcceptResult;
    });
}
