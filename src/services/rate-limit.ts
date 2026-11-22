import type { Context, MiddlewareHandler } from "hono";

interface Window {
    count: number;
    resetAt: number;
}

const windows = new Map<string, Window>();

function prune(now: number): void {
    for (const [key, window] of windows) {
        if (window.resetAt <= now) {
            windows.delete(key);
        }
    }
}

export function clientIp(c: Context): string {
    const forwarded = c.req.header("x-forwarded-for");

    if (forwarded) {
        const first = forwarded.split(",")[0]?.trim();
        if (first) return first;
    }

    const real = c.req.header("x-real-ip");
    if (real) return real.trim();

    const conn = (c.env as { connInfo?: { remoteAddr?: { hostname?: string } } } | undefined)?.connInfo;
    return conn?.remoteAddr?.hostname ?? "unknown";
}

export interface RateLimitOptions {
    bucket: string;
    limit: number;
    windowMs: number;
}

export function rateLimit(options: RateLimitOptions): MiddlewareHandler {
    const { bucket, limit, windowMs } = options;

    return async (c, next) => {
        const now = Date.now();

        if (windows.size > 10000) {
            prune(now);
        }

        const key = `${bucket}:${clientIp(c)}`;
        const existing = windows.get(key);

        if (!existing || existing.resetAt <= now) {
            windows.set(key, { count: 1, resetAt: now + windowMs });
            await next();
            return;
        }

        existing.count += 1;

        if (existing.count > limit) {
            const retryAfter = Math.max(1, Math.ceil((existing.resetAt - now) / 1000));

            c.header("Retry-After", String(retryAfter));
            c.header("Cache-Control", "no-store");

            // i mean i had to find somewhere to put it
            return c.json(
                {
                    error: "AAAAAAAAAAAAAAAAAAAAAAAA!!!!!!!!!!!!!!!!!!! AAAAAAAAAAAHhhhhhhhhhhhhhhhhhhhhhhhhhhH!!!!!!!!!!",
                },
                429,
            );
        }

        await next();
    };
}
