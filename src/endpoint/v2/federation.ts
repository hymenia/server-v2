
import { Hono } from "hono";
import { SERVER_ORIGIN } from "../../config/server.ts";
import { sql } from "../../db/client.ts";
import {
    signMessage,
    verifyMessageWithPublicKey,
} from "../../services/fedi-crypto.ts";
import { getTrustedServer } from "../../services/fedi-trust.ts";

const app = new Hono();

const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

interface PingEnvelope {
  type: string;
  origin: string;
  request_id: string;
  timestamp: string;
  payload: Record<string, unknown>;
}

function isValidUuid(value: unknown): value is string {
  return typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
      .test(value);
}

function isValidEnvelope(value: unknown): value is PingEnvelope {
  if (typeof value !== "object" || value === null) return false;

  const body = value as Record<string, unknown>;

  return body.type === "hymenia.ping" &&
    typeof body.origin === "string" &&
    typeof body.timestamp === "string" &&
    isValidUuid(body.request_id) &&
    typeof body.payload === "object" &&
    body.payload !== null &&
    !Array.isArray(body.payload);
}

function isValidOrigin(origin: string): boolean {
  try {
    const parsed = new URL(origin);
    return parsed.protocol === "https:" &&
      parsed.origin === origin &&
      parsed.username === "" &&
      parsed.password === "";
  } catch {
    return false;
  }
}

async function reserveRequest(
  origin: string,
  requestId: string,
): Promise<boolean> {
  // check timestamps first before removing old requests
  await sql`
    DELETE FROM federation_seen_requests
    WHERE received_at < NOW() - INTERVAL '15 minutes'
  `;

  const rows = await sql<{ request_id: string }[]>`
    INSERT INTO federation_seen_requests (origin, request_id)
    VALUES (${origin}, ${requestId}::uuid)
    ON CONFLICT (origin, request_id) DO NOTHING
    RETURNING request_id
  `;

  return rows.length === 1;
}

app.get("/key", async (c) => {
  try {
    const publicJwk = JSON.parse(
      await Deno.readTextFile(".secrets/fedi-public.json"),
    );

    if (
      publicJwk.kty !== "OKP" ||
      publicJwk.crv !== "Ed25519" ||
      typeof publicJwk.x !== "string" ||
      "d" in publicJwk
    ) {
      console.error("Invalid federation public key configuration");
      return c.json({ error: "Federation key unavailable" }, 500);
    }

    c.header("Cache-Control", "public, max-age=3600");

    return c.json({
      server: SERVER_ORIGIN,
      algorithm: "Ed25519",
      public_key: publicJwk,
    });
  } catch (error) {
    console.error("Failed to load federation public key:", error);
    return c.json({ error: "Federation key unavailable" }, 500);
  }
});

app.post("/ping", async (c) => {
  try {
    const signature = c.req.header("X-Hymenia-Signature");

    if (!signature) {
      return c.json({ error: "Missing signature" }, 401);
    }

    // verify before parsing
    const rawBody = await c.req.text();

    let parsed: unknown;

    try {
      parsed = JSON.parse(rawBody);
    } catch {
      return c.json({ error: "Invalid JSON" }, 400);
    }

    if (!isValidEnvelope(parsed)) {
      return c.json({ error: "Invalid message envelope" }, 400);
    }

    const message = parsed;

    if (!isValidOrigin(message.origin)) {
      return c.json({ error: "Invalid origin" }, 400);
    }

    const timestampMs = Date.parse(message.timestamp);

    if (
      !Number.isFinite(timestampMs) ||
      Math.abs(Date.now() - timestampMs) > MAX_CLOCK_SKEW_MS
    ) {
      return c.json({ error: "Timestamp outside allowed window" }, 401);
    }

    if (message.origin === SERVER_ORIGIN) {
      return c.json({ error: "Self-originated federation request" }, 400);
    }

    const trusted = await getTrustedServer(message.origin);

    if (!trusted) {
      return c.json({ error: "Untrusted server" }, 403);
    }

    const validSignature = await verifyMessageWithPublicKey(
      rawBody,
      signature,
      trusted.public_key,
    );

    if (!validSignature) {
      return c.json({ error: "Invalid signature" }, 401);
    }

    const reserved = await reserveRequest(
      message.origin,
      message.request_id,
    );

    if (!reserved) {
      return c.json({ error: "Duplicate request" }, 409);
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
    return c.json({ error: "Federation request failed" }, 500);
  }
});

export default app;
