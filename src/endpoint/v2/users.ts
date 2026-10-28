
import { Hono } from "hono";
import { sql } from "../../db/client.ts";

const app = new Hono();

interface PublicUser {
  username: string;
  created_at: string | Date;
}

// GET /v2/users/:username
app.get("/:username", async (c) => {
  const username = c.req.param("username").trim().toLowerCase();

  if (
    username.length < 3 ||
    username.length > 30 ||
    !/^[a-z0-9_]+(?:\.[a-z0-9_]+)*$/.test(username)
  ) {
    return c.json({ error: "Invalid username" }, 400);
  }

  try {
    const rows = await sql<PublicUser[]>`
      SELECT username, created_at
      FROM users
      WHERE username = ${username}
      LIMIT 1
    `;

    const user = rows[0];

    if (!user) {
      return c.json({ error: "User not found" }, 404);
    }

    c.header("Cache-Control", "public, max-age=60");

    return c.json({ user });
  } catch (error) {
    console.error("User lookup failed:", error);
    return c.json(
      { error: "User lookup temporarily unavailable" },
      500,
    );
  }
});

export default app;
