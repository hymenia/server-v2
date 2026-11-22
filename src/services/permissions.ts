import { sql } from "../db/client.ts";

export const PERMISSIONS = {
    messagesDelete: "messages.delete",
    membersKick: "members.kick",
    membersBan: "members.ban",
    membersManageRoles: "members.manage_roles",
    rolesManage: "roles.manage",
    invitesCreate: "invites.create",
    invitesManage: "invites.manage",
    channelsCreate: "channels.create",
    channelsManage: "channels.manage",
    channelsManageAccess: "channels.manage_access",
    spaceManage: "space.manage",
} as const;

export type PermissionId = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

// permissions granted to the default role when a space is created
export const DEFAULT_ROLE_PERMISSIONS: PermissionId[] = [
    PERMISSIONS.channelsCreate,
    PERMISSIONS.invitesCreate,
    PERMISSIONS.messagesDelete,
];

// the creator gets everything
export const OWNER_ROLE_PERMISSIONS: PermissionId[] = Object.values(PERMISSIONS);

export async function hasPermission(
    spaceId: string,
    actorId: string,
    permissionId: PermissionId,
): Promise<boolean> {
    const rows = await sql`
        SELECT 1
        FROM "v2".space_members m
        JOIN "v2".space_member_roles mr
          ON mr.space_id = m.space_id AND mr.actor_id = m.actor_id
        JOIN "v2".space_role_permissions rp
          ON rp.space_id = mr.space_id AND rp.role_id = mr.role_id
        WHERE m.space_id = ${spaceId}::uuid
          AND m.actor_id = ${actorId}::uuid
          AND m.membership_status = 'active'
          AND rp.permission_id = ${permissionId}
        LIMIT 1
    `;

    return rows.length > 0;
}

export async function grantRolePermissions(
    spaceId: string,
    roleId: string,
    permissionIds: readonly PermissionId[],
): Promise<void> {
    for (const permissionId of permissionIds) {
        await sql`
            INSERT INTO "v2".space_role_permissions (space_id, role_id, permission_id)
            VALUES (${spaceId}::uuid, ${roleId}::uuid, ${permissionId})
            ON CONFLICT (role_id, permission_id) DO NOTHING
        `;
    }
}

// same as above but inside a caller supplied transaction
export async function grantRolePermissionsTx(
    tx: { (strings: TemplateStringsArray, ...values: unknown[]): Promise<unknown> },
    spaceId: string,
    roleId: string,
    permissionIds: readonly PermissionId[],
): Promise<void> {
    for (const permissionId of permissionIds) {
        await tx`
            INSERT INTO "v2".space_role_permissions (space_id, role_id, permission_id)
            VALUES (${spaceId}::uuid, ${roleId}::uuid, ${permissionId})
            ON CONFLICT (role_id, permission_id) DO NOTHING
        `;
    }
}
