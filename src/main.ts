import { Hono } from "hono";

const app = new Hono();

app.get("/api/v2/health", (c) => {
  return c.json({
    status: "ok",
    version: "2",
  });
});

Deno.serve({ port: 8000 }, app.fetch);
