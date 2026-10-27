
import { serveStatic } from '@hono/deno';
import { Hono } from "hono";

const app = new Hono();

async function routeEndpoints( app: Hono, dir: URL, base = "", ):
 Promise<void> {
  const entries = [];

  for await (const entry of Deno.readDir(dir)) {
    entries.push(entry);
  }

  // keep it deterministic for testing and debugging
  entries.sort((a, b) => a.name.localeCompare(b.name));

  for (const entry of entries) {
    const path = new URL(
      entry.name + (entry.isDirectory ? "/" : ""),
      dir,
    );

    if (entry.isDirectory) {
      await routeEndpoints(app, path, `${base}/${entry.name}`);
      continue;
    }

    if (!entry.isFile || !entry.name.endsWith(".ts")) continue;

    const name = entry.name.replace(/\.ts$/, "");
    const route = name === "index" ? (base || "/") : `${base}/${name}`;
    const mod = await import(path.href);

    if (!(mod.default instanceof Hono)) {
      throw new Error(
        `Endpoint ${path.href} must default-export a Hono instance`,
      );
    }

    app.route(route, mod.default);
    console.log(`Registered ${route} -> ${path.href}`);
  }
}

await routeEndpoints(app, new URL("./endpoint/", import.meta.url));

app.get('/static/*', serveStatic({ root: './'}))

const port = Number(Deno.env.get("PORT") ?? "9071");

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error(`Invalid port: ${port}`);
}

Deno.serve({ hostname: "127.0.0.1", port }, app.fetch);

console.log(`Hyele listening on http://127.0.0.1:${port}`);
