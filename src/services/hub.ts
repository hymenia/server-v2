import type { WSContext } from "hono/ws";

const sockets = new Map<string, Set<WSContext>>(); // actorId -> sockets

export function addSocket(actorId: string, ws: WSContext) {
    let set = sockets.get(actorId);
    if (!set) sockets.set(actorId, (set = new Set()));
    set.add(ws);
}

export function removeSocket(actorId: string, ws: WSContext) {
    const set = sockets.get(actorId);
    if (!set) return;
    set.delete(ws);
    if (set.size === 0) sockets.delete(actorId);
}

export function sendToActors(actorIds: string[], type: string, data: unknown) {
    const frame = JSON.stringify({ type, data });
    for (const id of actorIds) {
        for (const ws of sockets.get(id) ?? []) ws.send(frame);
    }
}
