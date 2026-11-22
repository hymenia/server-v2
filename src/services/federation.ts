import type { Context } from "hono";
import type { JSONValue } from "postgres";
import { SERVER_ORIGIN } from "../config/server.ts";
import { sql } from "../db/client.ts";
import { signMessage, verifyMessageWithPublicKey } from "./fedi-crypto.ts";
import { getTrustedServer } from "./fedi-trust.ts";

export const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
export const MAX_BODY_SIZE = 64 * 1024;

export interface Envelope {
    type: string;
    origin: string;
    request_id: string;
    timestamp: string;
    payload: Record<string, unknown>;
}

export function isValidUuid(value: unknown): value is string {
    return (
        typeof value === "string" &&
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
    );
}

export function isValidOrigin(origin: string): boolean {
    try {
        const parsed = new URL(origin);

        return (
            parsed.protocol === "https:" &&
            parsed.origin === origin &&
            parsed.username === "" &&
            parsed.password === "" &&
            parsed.pathname === "/" &&
            parsed.search === "" &&
            parsed.hash === ""
        );
    } catch {
        return false;
    }
}

export function isValidEnvelope(value: unknown, type: string): value is Envelope {
    if (typeof value !== "object" || value === null) return false;

    const body = value as Record<string, unknown>;

    return (
        body.type === type &&
        typeof body.origin === "string" &&
        typeof body.timestamp === "string" &&
        isValidUuid(body.request_id) &&
        typeof body.payload === "object" &&
        body.payload !== null &&
        !Array.isArray(body.payload)
    );
}

export async function reserveRequest(origin: string, requestId: string): Promise<boolean> {
    const rows = await sql<{ request_id: string }[]>`
        INSERT INTO "v2".federation_seen_requests (origin, request_id)
        VALUES (${origin}, ${requestId}::uuid)
        ON CONFLICT (origin, request_id) DO NOTHING
        RETURNING request_id
    `;

    if (rows.length !== 1) return false;

    await sql`
        DELETE FROM "v2".federation_seen_requests
        WHERE received_at < NOW() - (15 * INTERVAL '1 minute')
    `;

    return true;
}

export type VerifyResult =
    | { ok: true; envelope: Envelope; rawBody: string }
    | { ok: false; status: number; error: string };

export async function verifyFederationRequest(c: Context, expectedType: string): Promise<VerifyResult> {
    const signature = c.req.header("X-Hymenia-Signature");

    if (!signature) {
        return { ok: false, status: 401, error: "Missing signature" };
    }

    if (signature.length > 256) {
        return { ok: false, status: 400, error: "Invalid signature" };
    }

    const rawBody = await c.req.text();

    if (new TextEncoder().encode(rawBody).length > MAX_BODY_SIZE) {
        return { ok: false, status: 413, error: "Request too large" };
    }

    let parsed: unknown;

    try {
        parsed = JSON.parse(rawBody);
    } catch {
        return { ok: false, status: 400, error: "Invalid JSON" };
    }

    if (!isValidEnvelope(parsed, expectedType)) {
        return { ok: false, status: 400, error: "Invalid message envelope" };
    }

    const envelope = parsed;

    if (!isValidOrigin(envelope.origin)) {
        return { ok: false, status: 400, error: "Invalid origin" };
    }

    const timestampMs = Date.parse(envelope.timestamp);

    if (!Number.isFinite(timestampMs) || Math.abs(Date.now() - timestampMs) > MAX_CLOCK_SKEW_MS) {
        return { ok: false, status: 401, error: "Timestamp outside allowed window" };
    }

    if (new URL(envelope.origin).host.toLowerCase() === new URL(SERVER_ORIGIN).host.toLowerCase()) {
        return { ok: false, status: 400, error: "Self-originated federation request" };
    }

    const trusted = await getTrustedServer(envelope.origin);

    if (!trusted) {
        return { ok: false, status: 403, error: "Untrusted server" };
    }

    const validSignature = await verifyMessageWithPublicKey(rawBody, signature, trusted.public_key);

    if (!validSignature) {
        return { ok: false, status: 401, error: "Invalid signature" };
    }

    const reserved = await reserveRequest(envelope.origin, envelope.request_id);

    if (!reserved) {
        return { ok: false, status: 409, error: "Duplicate request" };
    }

    return { ok: true, envelope, rawBody };
}

export async function signEnvelope(
    type: string,
    requestId: string,
    payload: Record<string, unknown>,
): Promise<{ body: string; signature: string }> {
    const body = JSON.stringify({
        type,
        origin: SERVER_ORIGIN,
        request_id: requestId,
        timestamp: new Date().toISOString(),
        payload,
    });

    return { body, signature: await signMessage(body) };
}

export async function enqueueOutbox(
    eventType: string,
    objectUri: string,
    actorUri: string,
    payload: Record<string, unknown>,
): Promise<void> {
    await sql`
        INSERT INTO "v2".federation_outbox (event_type, object_uri, actor_uri, payload)
        VALUES (${eventType}, ${objectUri}, ${actorUri}, ${sql.json(payload as JSONValue)})
    `;
}
