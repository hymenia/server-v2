
import postgres from "postgres";

const databaseUrl = Deno.env.get("DATABASE_URL");

if (!databaseUrl) {
  throw new Error("DATABASE_URL is required");
}

const sql = postgres(databaseUrl, {
  max: 1,
  connect_timeout: 10,
});

const migrationsDir = new URL("./migrations/", import.meta.url);

try {
  await sql`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name TEXT PRIMARY KEY,
      checksum TEXT NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;

  const migrations: { name: string; path: URL }[] = [];

  for await (const entry of Deno.readDir(migrationsDir)) {
    if (entry.isFile && entry.name.endsWith(".sql")) {
      migrations.push({
        name: entry.name,
        path: new URL(entry.name, migrationsDir),
      });
    }
  }

  migrations.sort((a, b) => a.name.localeCompare(b.name));

  for (const migration of migrations) {
    const source = await Deno.readTextFile(migration.path);
    const checksumBuffer = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(source),
    );
    const checksum = Array.from(new Uint8Array(checksumBuffer))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");

    const existing = await sql`
      SELECT checksum
      FROM schema_migrations
      WHERE name = ${migration.name}
    `;

    if (existing.length > 0) {
      if (existing[0].checksum !== checksum) {
        throw new Error(
          `Applied migration changed: ${migration.name} ` +
          "Don't edit migrations after they have been applied and instead make a new one",
        );
      }

      console.log(`SKIP ${migration.name}`);
      continue;
    }

    console.log(`APPLY ${migration.name}`);

    await sql.begin(async (tx) => {
      await tx.unsafe(source);

      await tx`
        INSERT INTO schema_migrations (name, checksum)
        VALUES (${migration.name}, ${checksum})
      `;
    });

    console.log(`DONE ${migration.name}`);
  }

  console.log("All migrations completed");
} finally {
  await sql.end();
}
