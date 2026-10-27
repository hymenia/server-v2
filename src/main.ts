import { Hono } from "hono";
import { serveStatic } from '@hono/deno'

const app = new Hono();

async function routeEndpoints(app:Hono, dir: URL, base = '') {
    // I stole this code from another project I had -Hazel
    for await (const entry of Deno.readDir(dir)) {
        const path = new URL(entry.name + (entry.isDirectory ? '/' : ''), dir)

        if (entry.isDirectory) {
            // stupid
            await routeEndpoints(app, path, `${base}/${entry.name}`)
            continue
        }

        if (!entry.isFile || !entry.name.endsWith('.ts')) continue
        
        const name = entry.name.replace(/\.ts$/, '')
        const route = name === 'index' ? (base || '/') : `${base}/${name}`
        const mod = await import(path.href)

        app.route(route, mod.default)
    }
}

await routeEndpoints(app, new URL("./endpoint/", import.meta.url))

app.get('/static/*', serveStatic({ root: './'}))

Deno.serve(app.fetch)
