import { Hono } from "hono";
import type { JSONValue } from "postgres";
import { SERVER_ORIGIN } from "../../config/server.ts";
import { sql } from "../../db/client.ts";
import { ensureRemoteActor } from "../../services/actors.ts";
import { enqueueOutbox, signEnvelope, verifyFederationRequest } from "../../services/federation.ts";
import { signMessage, verifyMessageWithPublicKey } from "../../services/fedi-crypto.ts";
import { getTrustedServer } from "../../services/fedi-trust.ts";
import { acceptInvite } from "../../services/invites.ts";

const app = new Hono();

const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_BODY_SIZE = 64 * 1024;
const REQUEST_RETENTION_MINUTES = 15;

interface PingEnvelope {
    type: string;
    origin: string;
    request_id: string;
    timestamp: string;
    payload: Record<string, unknown>;
}

function isValidUuid(value: unknown): value is string {
    return (
        typeof value === "string" &&
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
    );
}

function isValidEnvelope(value: unknown): value is PingEnvelope {
    if (typeof value !== "object" || value === null) return false;

    const body = value as Record<string, unknown>;

    return (
        body.type === "hymenia.ping" &&
        typeof body.origin === "string" &&
        typeof body.timestamp === "string" &&
        isValidUuid(body.request_id) &&
        typeof body.payload === "object" &&
        body.payload !== null &&
        !Array.isArray(body.payload)
    );
}

function isValidOrigin(origin: string): boolean {
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

async function reserveRequest(origin: string, requestId: string): Promise<boolean> {
    const rows = await sql<{ request_id: string }[]>`
    INSERT INTO "v2".federation_seen_requests (
      origin,
      request_id
    )
    VALUES (
      ${origin},
      ${requestId}::uuid
    )
    ON CONFLICT (origin, request_id) DO NOTHING
    RETURNING request_id
  `;

    if (rows.length !== 1) return false;

    await sql`
    DELETE FROM "v2".federation_seen_requests
    WHERE received_at < NOW() -
      (${REQUEST_RETENTION_MINUTES} * INTERVAL '1 minute')
  `;

    return true;
}

app.get("/key", async c => {
    try {
        const publicJwk = JSON.parse(await Deno.readTextFile(".secrets/fedi-public.json"));

        if (
            publicJwk.kty !== "OKP" ||
            publicJwk.crv !== "Ed25519" ||
            typeof publicJwk.x !== "string" ||
            !/^[A-Za-z0-9_-]+$/.test(publicJwk.x) ||
            "d" in publicJwk
        ) {
            console.error("Invalid federation public key configuration");

            return c.json(
                {
                    error: "Federation key unavailable",
                },
                500,
            );
        }

        c.header("Cache-Control", "public, max-age=3600");

        return c.json({
            server: SERVER_ORIGIN,
            algorithm: "Ed25519",
            public_key: publicJwk,
        });
    } catch (error) {
        console.error("Failed to load federation public key:", error);

        return c.json(
            {
                error: "Federation key unavailable",
            },
            500,
        );
    }
});

app.post("/ping", async c => {
    try {
        const signature = c.req.header("X-Hymenia-Signature");

        if (!signature) {
            return c.json(
                {
                    error: "Missing signature",
                },
                401,
            );
        }

        if (signature.length > 256) {
            return c.json(
                {
                    error: "Invalid signature",
                },
                400,
            );
        }

        const rawBody = await c.req.text();

        if (new TextEncoder().encode(rawBody).length > MAX_BODY_SIZE) {
            return c.json(
                {
                    error: "Request too large",
                },
                413,
            );
        }

        let parsed: unknown;

        try {
            parsed = JSON.parse(rawBody);
        } catch {
            return c.json(
                {
                    error: "Invalid JSON",
                },
                400,
            );
        }

        if (!isValidEnvelope(parsed)) {
            return c.json(
                {
                    error: "Invalid message envelope",
                },
                400,
            );
        }

        const message = parsed;

        if (!isValidOrigin(message.origin)) {
            return c.json(
                {
                    error: "Invalid origin",
                },
                400,
            );
        }

        const timestampMs = Date.parse(message.timestamp);

        if (!Number.isFinite(timestampMs) || Math.abs(Date.now() - timestampMs) > MAX_CLOCK_SKEW_MS) {
            return c.json(
                {
                    error: "Timestamp outside allowed window",
                },
                401,
            );
        }

        if (new URL(message.origin).host.toLowerCase() === new URL(SERVER_ORIGIN).host.toLowerCase()) {
            return c.json(
                {
                    error: "Self-originated federation request",
                },
                400,
            );
        }

        const trusted = await getTrustedServer(message.origin);

        if (!trusted) {
            return c.json(
                {
                    error: "Untrusted server",
                },
                403,
            );
        }

        const validSignature = await verifyMessageWithPublicKey(rawBody, signature, trusted.public_key);

        if (!validSignature) {
            return c.json(
                {
                    error: "Invalid signature",
                },
                401,
            );
        }

        const reserved = await reserveRequest(message.origin, message.request_id);

        if (!reserved) {
            return c.json(
                {
                    error: "Duplicate request",
                },
                409,
            );
        }

        const responseBody = JSON.stringify({
            type: "hymenia.ping.response",
            origin: SERVER_ORIGIN,
            request_id: message.request_id,
            timestamp: new Date().toISOString(),
            payload: {
                status: "ok",
            },
        });

        const responseSignature = await signMessage(responseBody);

        c.header("Content-Type", "application/json; charset=utf-8");
        c.header("Cache-Control", "no-store");
        c.header("X-Hymenia-Signature", responseSignature);

        return c.body(responseBody, 200);
    } catch (error) {
        console.error("Ping failed:", error);

        return c.json(
            {
                error: "Federation request failed",
            },
            500,
        );
    }
});

// POST /v2/federation/inbox
// stores a signed event from a trusted server for later processing
app.post("/inbox", async c => {
    try {
        const verified = await verifyFederationRequest(c, "hymenia.event");

        if (!verified.ok) {
            return c.json({ error: verified.error }, verified.status as 400);
        }

        const signature = c.req.header("X-Hymenia-Signature") ?? "";
        const base64 = signature.replaceAll("-", "+").replaceAll("_", "/");
        const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
        const signatureBytes = Uint8Array.from(atob(padded), char => char.charCodeAt(0));

        await sql`
            INSERT INTO "v2".federation_inbox (
                origin, request_id, key_id, event_type, payload, signature
            )
            VALUES (
                ${verified.envelope.origin},
                ${verified.envelope.request_id}::uuid,
                ${"default"},
                ${String(verified.envelope.payload.event_type ?? "unknown")},
                ${sql.json(verified.envelope.payload as JSONValue)},
                ${signatureBytes}
            )
            ON CONFLICT (origin, request_id) DO NOTHING
        `;

        c.header("Cache-Control", "no-store");
        return c.json({ success: true });
    } catch (error) {
        console.error("Inbox store failed:", error);
        return c.json({ error: "Inbox store failed" }, 500);
    }
});

// POST /v2/federation/invites/accept
// a remote actor redeems an invite on this server
app.post("/invites/accept", async c => {
    try {
        const verified = await verifyFederationRequest(c, "hymenia.invite.accept");

        if (!verified.ok) {
            return c.json({ error: verified.error }, verified.status as 400);
        }

        const code = typeof verified.envelope.payload.code === "string" ? verified.envelope.payload.code : "";
        const actorUri =
            typeof verified.envelope.payload.actor_uri === "string" ? verified.envelope.payload.actor_uri : "";

        if (!code || !actorUri) {
            return c.json({ error: "Invalid payload" }, 400);
        }

        const actor = await ensureRemoteActor(actorUri);

        if (!actor) {
            return c.json({ error: "Invalid actor uri" }, 400);
        }

        // the actor must belong to the server that signed the request
        if (new URL(actorUri).host.toLowerCase() !== new URL(verified.envelope.origin).host.toLowerCase()) {
            return c.json({ error: "Actor does not match origin" }, 403);
        }

        const result = await acceptInvite(code, actor.id);

        if (!result.ok) {
            return c.json({ error: result.error }, result.status as 400);
        }

        if (!result.alreadyMember) {
            await enqueueOutbox("space.member.joined", `${SERVER_ORIGIN}/spaces/${result.spaceId}`, actor.actor_uri, {
                space_id: result.spaceId,
                actor_uri: actor.actor_uri,
            });
        }

        const response = await signEnvelope("hymenia.invite.accept.response", verified.envelope.request_id, {
            space_id: result.spaceId,
            actor_uri: actor.actor_uri,
            already_member: result.alreadyMember,
        });

        c.header("Content-Type", "application/json; charset=utf-8");
        c.header("Cache-Control", "no-store");
        c.header("X-Hymenia-Signature", response.signature);

        return c.body(response.body, 200);
    } catch (error) {
        console.error("Federated invite accept failed:", error);
        return c.json({ error: "Federated invite accept failed" }, 500);
    }
});

export default app;
