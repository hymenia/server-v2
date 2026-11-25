import { compare as compareBcrypt } from "bcryptjs";

// v1 accounts store bcryptjs hashes, v2 stores pbkdf2
// this is just so users dont have to change their password
const BCRYPT_HASH = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;

const PBKDF2_ITERATIONS = 600_000;

export function isBcryptHash(stored: string): boolean {
    return BCRYPT_HASH.test(stored);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    const buffer = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(buffer).set(bytes);
    return buffer;
}

function toHex(bytes: Uint8Array): string {
    return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(value: string): Uint8Array {
    return new Uint8Array((value.match(/.{2}/g) ?? []).map(x => parseInt(x, 16)));
}

async function derive(password: string, salt: Uint8Array): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, [
        "deriveBits",
    ]);

    const bits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            hash: "SHA-256",
            salt: toArrayBuffer(salt),
            iterations: PBKDF2_ITERATIONS,
        },
        key,
        256,
    );

    return new Uint8Array(bits);
}

export async function hashPassword(password: string): Promise<string> {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const derived = await derive(password, salt);

    return `pbkdf2$${toHex(salt)}$${toHex(derived)}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
    if (BCRYPT_HASH.test(stored)) {
        try {
            return await compareBcrypt(password, stored);
        } catch {
            return false;
        }
    }

    const parts = stored.split("$");
    if (parts.length !== 3 || parts[0] !== "pbkdf2") return false;

    const saltHex = parts[1];
    const expectedHex = parts[2];

    if (!saltHex || !expectedHex || !/^[0-9a-f]{32}$/.test(saltHex) || !/^[0-9a-f]{64}$/.test(expectedHex)) {
        return false;
    }

    const expected = fromHex(expectedHex);
    const actual = await derive(password, fromHex(saltHex));

    let difference = actual.length ^ expected.length;

    for (let i = 0; i < Math.min(actual.length, expected.length); i++) {
        difference |= (actual[i] ?? 0) ^ (expected[i] ?? 0);
    }

    return difference === 0;
}
