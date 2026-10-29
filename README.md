# hyele

The second version of the backend for Hymenia, written in Typescript and utilising Deno, Hono and Zod.

## Development

Make sure you have Deno, Git and PostgreSQL installed.
You'll also need a mail server.

Create the database:

```bash
createdb hymenia_dev
```

Run the migrator:

```bash
deno run --env-file=.env --allow-read --allow-env=DATABASE_URL --allow-net src/db/migrate.ts
```
Copy the .env.example to .env:

```bash
cp .env.example .env
```

Then fill it in. Afterwards,
start the development server:

```bash
deno task dev
```

Go to `https://[PUBLIC_BASE_URL]/v2/` in a web browser to check it's online.

Check types:

```bash
deno task check
```
