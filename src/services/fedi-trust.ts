import { sql } from "../db/client.ts";

export interface TrustedFederationServer {
  origin: string;
  public_key: {
    kty: string;
    crv: string;
    x: string;
  };
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export async function getTrustedServer(
  origin: string,
): Promise<TrustedFederationServer | null> {
  const rows = await sql<{ origin: string; public_key: Uint8Array }[]>`
    SELECT origin, public_key
    FROM trusted_federation_servers
    WHERE origin = ${origin}
    LIMIT 1
  `;

  const row = rows[0];

  if (!row) {
    return null;
  }

  // the column holds 32 raw ed25519 bytes, the verifier wants a jwk
  return {
    origin: row.origin,
    public_key: {
      kty: "OKP",
      crv: "Ed25519",
      x: toBase64Url(row.public_key),
    },
  };
}
