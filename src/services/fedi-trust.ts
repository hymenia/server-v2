
import { sql } from "../db/client.ts";

export interface TrustedFederationServer {
  instance_id: string;
  origin: string;
  public_key: {
    kty: string;
    crv: string;
    x: string;
  };
}

export async function getTrustedServer(
  origin: string,
): Promise<TrustedFederationServer | null> {
  const rows = await sql<TrustedFederationServer[]>`
    SELECT instance_id, origin, public_key
    FROM trusted_federation_servers
    WHERE origin = ${origin}
    LIMIT 1
  `;

  return rows[0] ?? null;
}
