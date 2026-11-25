import { Hono } from "hono";
import { sql } from "../../db/client.ts";

const app = new Hono();

const AVATAR_DATA_URL = /^data:image\/(png|jpe?g|webp|gif);base64,([A-Za-z0-9+/=]+)$/;

let defaultAvatar: { bytes: Uint8Array; etag: string } | null = null;

async function etagOf(bytes: Uint8Array): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", bytes as unknown as ArrayBuffer);
    return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}

async function getDefaultAvatar(): Promise<{ bytes: Uint8Array; etag: string }> {
    if (defaultAvatar) return defaultAvatar;

    const bytes = await Deno.readFile(new URL("../../../assets/default-avatar.png", import.meta.url));
    defaultAvatar = { bytes, etag: await etagOf(bytes) };
    return defaultAvatar;
}

function decodeBase64(value: string): Uint8Array {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

// GET /v2/avatar/:username
app.get("/:username", async c => {
    const username = c.req.param("username").trim().toLowerCase();
    const ifNoneMatch = c.req.header("If-None-Match");

    const send = (bytes: Uint8Array, mime: string, etag: string) => {
        c.header("Content-Type", mime);
        c.header("Cache-Control", "public, max-age=300, must-revalidate");
        c.header("ETag", etag);

        if (ifNoneMatch === etag) return c.body(null, 304);

        return c.body(bytes as unknown as ArrayBuffer, 200);
    };

    try {
        if (username.length === 0) {
            const fallback = await getDefaultAvatar();
            return send(fallback.bytes, "image/png", fallback.etag);
        }

        const rows = await sql<{ avatar_url: string | null }[]>`
            select avatar_url from users where username = ${username} limit 1
        `;

        const avatarUrl = rows[0]?.avatar_url;
        const match = avatarUrl ? avatarUrl.match(AVATAR_DATA_URL) : null;

        if (!match) {
            const fallback = await getDefaultAvatar();
            return send(fallback.bytes, "image/png", fallback.etag);
        }

        const mime = `image/${match[1]}`;
        const bytes = decodeBase64(match[2] ?? "");

        return send(bytes, mime, await etagOf(bytes));
    } catch (error) {
        console.error("Avatar lookup failed:", error);

        const fallback = await getDefaultAvatar();
        return send(fallback.bytes, "image/png", fallback.etag);
    }
});

export default app;
