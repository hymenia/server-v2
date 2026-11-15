import type { Context } from "hono";
import { sql } from "../db/client.ts";

export const COOKIE = "__Host-hymenia_session";

export interface PublicUser {
    id: string;
    username: string;
    email: string;
}

export interface ActorRow {
    id: string;
    actor_uri: string;
}

export interface AuthUser {
    user: PublicUser;
    actor: ActorRow;
}

export function readToken(c: Context): string | null {
    const cookie = c.req.header("Cookie") ?? "";
    const prefix = COOKIE + "=";

    const item = cookie
        .split(";")
        .map(v => v.trim())
        .find(v => v.startsWith(prefix));

    const token = item?.slice(prefix.length);
    return token && /^[0-9a-f]{64}$/.test(token) ? token : null;
}

export async function hash(value: string): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
    return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}

export async function findUser(c: Context): Promise<PublicUser | null> {
    const token = readToken(c);
    if (!token) return null;

    const rows = await sql<PublicUser[]>`
        select u.id, u.username, u.email
        from public.sessions s
        join public.users u on u.id = s.user_id
        where s.token_hash = ${await hash(token)}
          and s.expires_at > now()
        limit 1
    `;
    return rows[0] ?? null;
}

export async function getAuthUser(c: Context): Promise<AuthUser | null> {
    const user = await findUser(c);
    if (!user) return null;

    const actors = await sql<ActorRow[]>`
        select id, actor_uri
        from "v2".actors
        where local_user_id = ${user.id}
          and is_active = true
        limit 1
    `;

    const actor = actors[0];
    return actor ? { user, actor } : null;
}
