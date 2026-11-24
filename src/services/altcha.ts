import { createChallenge, verifySolution } from "altcha-lib";
import { deriveKey } from "altcha-lib/algorithms/pbkdf2";

const CHALLENGE_COST = 5000;

interface AltchaSecrets {
    hmacSignatureSecret: string;
    hmacKeySignatureSecret?: string;
}

function readSecrets(): AltchaSecrets | null {
    const signature = Deno.env.get("ALTCHA_HMAC_SECRET") ?? Deno.env.get("ALTCHA_HMAC_KEY");

    if (!signature) {
        return null;
    }

    const keySecret = Deno.env.get("ALTCHA_KEY_SECRET");

    return keySecret
        ? { hmacSignatureSecret: signature, hmacKeySignatureSecret: keySecret }
        : { hmacSignatureSecret: signature };
}

let warned = false;

export function altchaEnabled(): boolean {
    const secrets = readSecrets();

    if (!secrets && !warned) {
        warned = true;
        console.warn("ALTCHA_HMAC_SECRET is not set, captcha verification is disabled");
    }

    return secrets !== null;
}

export async function createAltchaChallenge(): Promise<Record<string, unknown> | null> {
    const secrets = readSecrets();

    if (!secrets) {
        return null;
    }

    return (await createChallenge({
        algorithm: "PBKDF2/SHA-256",
        cost: CHALLENGE_COST,
        deriveKey,
        ...secrets,
    })) as unknown as Record<string, unknown>;
}

function decodePayload(payload: string): { challenge: unknown; solution: unknown } | null {
    try {
        const json = atob(payload);
        const parsed = JSON.parse(json) as { challenge?: unknown; solution?: unknown };

        if (!parsed || typeof parsed !== "object") {
            return null;
        }

        if (!parsed.challenge || !parsed.solution) {
            return null;
        }

        return { challenge: parsed.challenge, solution: parsed.solution };
    } catch {
        return null;
    }
}

export async function verifyAltchaPayload(payload: unknown): Promise<boolean> {
    const secrets = readSecrets();

    // no secret configured means captcha is off, not that every request fails
    if (!secrets) {
        return true;
    }

    if (typeof payload !== "string" || payload.length === 0 || payload.length > 8192) {
        return false;
    }

    const decoded = decodePayload(payload);

    if (!decoded) {
        return false;
    }

    try {
        const result = await verifySolution({
            challenge: decoded.challenge as never,
            solution: decoded.solution as never,
            deriveKey,
            ...secrets,
        });

        return result.verified === true;
    } catch (error) {
        console.error("altcha verification failed:", error);
        return false;
    }
}
