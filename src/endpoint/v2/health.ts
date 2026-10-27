import { Hono } from "hono";

const app = new Hono();

app.get("/", (c) => {
  return c.json({
    status: "ok",
    version: "2",
  });
});

export default app