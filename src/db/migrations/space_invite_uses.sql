-- records which actor consumed which invite
-- keeps accepts idempotent across federation retries

create schema if not exists "v2";

CREATE TABLE IF NOT EXISTS "v2".space_invite_uses (
    invite_id UUID NOT NULL
        REFERENCES "v2".space_invites(id)
        ON DELETE CASCADE,
    actor_id UUID NOT NULL
        REFERENCES "v2".actors(id)
        ON DELETE CASCADE,
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (invite_id, actor_id)
);

CREATE INDEX IF NOT EXISTS space_invite_uses_actor_idx
ON "v2".space_invite_uses (actor_id);
