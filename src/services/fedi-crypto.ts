
const PRIVATE_KEY_PATH = ".secrets/fedi-private.json";
const PUBLIC_KEY_PATH = ".secrets/fedi-public.json";

const encoder = new TextEncoder();

interface Ed25519Jwk {
  kty: string;
  crv: string;
  x: string;
  d?: string;
  ext?: boolean;
  key_ops?: string[];
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

async function loadPrivateKey(): Promise<CryptoKey> {
  const jwk = JSON.parse(
    await Deno.readTextFile(PRIVATE_KEY_PATH),
  ) as Ed25519Jwk;

  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.d) {
    throw new Error("Invalid Ed25519 private key");
  }

  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
}

async function loadPublicKey(): Promise<CryptoKey> {
  const jwk = JSON.parse(
    await Deno.readTextFile(PUBLIC_KEY_PATH),
  ) as Ed25519Jwk;

  if (
    jwk.kty !== "OKP" ||
    jwk.crv !== "Ed25519" ||
    typeof jwk.x !== "string" ||
    "d" in jwk
  ) {
    throw new Error("Invalid Ed25519 public key");
  }

  return await importPublicKey(jwk);
}

async function importPublicKey(jwk: Ed25519Jwk): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "jwk",
    {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      ext: true,
      key_ops: ["verify"],
    },
    { name: "Ed25519" },
    false,
    ["verify"],
  );
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Invalid base64url signature");
  }

  const base64 = value
    .replaceAll("-", "+")
    .replaceAll("_", "/");

  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);

  return Uint8Array.from(
    atob(padded),
    (char) => char.charCodeAt(0),
  );
}

export async function signMessage(message: string): Promise<string> {
  const key = await loadPrivateKey();

  const signature = await crypto.subtle.sign(
    "Ed25519",
    key,
    toArrayBuffer(encoder.encode(message)),
  );

  return toBase64Url(new Uint8Array(signature));
}

export async function verifyMessage(
  message: string,
  signature: string,
): Promise<boolean> {
  try {
    const key = await loadPublicKey();

    return await crypto.subtle.verify(
      "Ed25519",
      key,
      toArrayBuffer(fromBase64Url(signature)),
      toArrayBuffer(encoder.encode(message)),
    );
  } catch {
    return false;
  }
}

export async function verifyMessageWithPublicKey(
  message: string,
  signature: string,
  jwk: Ed25519Jwk,
): Promise<boolean> {
  try {
    if (
      jwk.kty !== "OKP" ||
      jwk.crv !== "Ed25519" ||
      typeof jwk.x !== "string" ||
      "d" in jwk
    ) {
      return false;
    }

    const key = await importPublicKey(jwk);

    return await crypto.subtle.verify(
      "Ed25519",
      key,
      toArrayBuffer(fromBase64Url(signature)),
      toArrayBuffer(encoder.encode(message)),
    );
  } catch {
    return false;
  }
}
