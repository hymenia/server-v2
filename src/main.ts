import { serveStatic, upgradeWebSocket } from "@hono/deno";
import { Hono } from "hono";
import { type AuthUser, getAuthUser } from "./services/auth.ts";
import { addSocket, removeSocket } from "./services/hub.ts";

const app = new Hono();

async function routeEndpoints(app: Hono, dir: URL, base = ""): Promise<void> {
    const entries = [];

    for await (const entry of Deno.readDir(dir)) {
        entries.push(entry);
    }

    // keep it deterministic for testing and debugging
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
        const path = new URL(entry.name + (entry.isDirectory ? "/" : ""), dir);

        if (entry.isDirectory) {
            await routeEndpoints(app, path, `${base}/${entry.name}`);
            continue;
        }

        if (!entry.isFile || !entry.name.endsWith(".ts")) continue;

        const name = entry.name.replace(/\.ts$/, "");
        const route = name === "index" ? base || "/" : `${base}/${name}`;
        const mod = await import(path.href);

        if (!(mod.default instanceof Hono)) {
            throw new Error(`Endpoint ${path.href} must default-export a Hono instance`);
        }

        app.route(route, mod.default);
        console.log(`Registered ${route} -> ${path.href}`);
    }
}

await routeEndpoints(app, new URL("./endpoint/", import.meta.url));

const ALLOWED_ORIGINS = (Deno.env.get("ALLOWED_ORIGINS") ?? "http://localhost:5173")
    .split(",")
    .map(origin => origin.trim());

const ws = new Hono<{ Variables: { auth: AuthUser } }>();

ws.get(
    "/ws",
    async (c, next) => {
        const origin = c.req.header("Origin");
        if (!origin || !ALLOWED_ORIGINS.includes(origin)) {
            return c.text("forbidden", 403);
        }

        const auth = await getAuthUser(c);
        if (!auth) return c.text("unauthorized", 401);

        c.set("auth", auth);
        await next();
    },
    upgradeWebSocket(c => {
        const auth = c.get("auth");
        return {
            onOpen(_event, socket) {
                addSocket(auth.actor.id, socket);
            },
            onClose(_event, socket) {
                removeSocket(auth.actor.id, socket);
            },
            onMessage(event, socket) {
                if (event.data === "ping") socket.send("pong");
            },
        };
    }),
);

app.route("/", ws);

app.get("/static/*", serveStatic({ root: "./" }));

const port = Number(Deno.env.get("PORT") ?? "9071");

if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid port: ${port}`);
}

Deno.serve({ hostname: "127.0.0.1", port }, app.fetch);

console.log(`Hymenia Server v2 listening on http://127.0.0.1:${port}`);
