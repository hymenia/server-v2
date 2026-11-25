CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Users
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(30) NOT NULL,
    host TEXT,
    email VARCHAR(254),
    email_verified_at TIMESTAMPTZ,
    password_hash TEXT,
    -- local accounts keep their keys on v2.actors
    public_key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT users_host_lowercase
        CHECK (host IS NULL OR host = LOWER(host))
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS host TEXT;

ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(254);

ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;

ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;

ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key TEXT;

ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'users_host_lowercase'
          AND conrelid = 'public.users'::regclass
    ) THEN
        ALTER TABLE public.users
            ADD CONSTRAINT users_host_lowercase
            CHECK (host IS NULL OR host = LOWER(host));
    END IF;
END
$$;

DO $$
DECLARE
    clashes TEXT;
BEGIN
    SELECT string_agg(LOWER(username) || ' (' || n || ' rows)', ', ')
    INTO clashes
    FROM (
        SELECT LOWER(username) AS username, COUNT(*) AS n
        FROM public.users
        GROUP BY LOWER(username)
        HAVING COUNT(*) > 1
    ) dupes;

    IF clashes IS NOT NULL THEN
        RAISE EXCEPTION
            'duplicate usernames that differ only by case: %. rename them before migrating.',
            clashes;
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS users_username_host_unique
    ON users (LOWER(username), COALESCE(host, ''));

CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_unique
    ON users (LOWER(email))
    WHERE email IS NOT NULL;


-- sessions
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS sessions_user_id_idx
    ON sessions (user_id);

CREATE INDEX IF NOT EXISTS sessions_expires_at_idx
    ON sessions (expires_at);


-- email verification
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS email_verification_tokens_user_id_idx
    ON email_verification_tokens (user_id);

CREATE INDEX IF NOT EXISTS email_verification_tokens_expires_at_idx
    ON email_verification_tokens (expires_at);


-- federation replay protection
CREATE TABLE IF NOT EXISTS federation_seen_requests (
    origin TEXT NOT NULL,
    request_id UUID NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (origin, request_id)
);

CREATE INDEX IF NOT EXISTS federation_seen_requests_received_at_idx
    ON federation_seen_requests (received_at);


-- trusted federation servers
CREATE TABLE IF NOT EXISTS trusted_federation_servers (
    origin TEXT PRIMARY KEY,
    public_key BYTEA NOT NULL,
    trusted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT trusted_federation_origin_https
        CHECK (origin ~ '^https://[^/]+$'),

    CONSTRAINT trusted_federation_public_key_length
        CHECK (octet_length(public_key) = 32)
);


CREATE TABLE IF NOT EXISTS server_keys (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    private_key BYTEA NOT NULL CHECK (octet_length(private_key) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE SCHEMA IF NOT EXISTS "v2";

-- server identity
CREATE TABLE IF NOT EXISTS "v2".server_identity (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    host TEXT NOT NULL UNIQUE,
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    key_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT server_identity_host_lowercase
        CHECK (host = LOWER(host)),

    CONSTRAINT server_identity_host_format
        CHECK (host !~ '[/@?#]')
);

-- federation servers
CREATE TABLE IF NOT EXISTS "v2".federation_servers (
    host TEXT PRIMARY KEY,
    trust_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (trust_status IN ('pending', 'trusted', 'blocked')),
    trusted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT federation_servers_host_lowercase
        CHECK (host = LOWER(host)),

    CONSTRAINT federation_servers_host_format
        CHECK (host !~ '[/@?#]')
);

-- trusted federation keys
CREATE TABLE IF NOT EXISTS "v2".federation_server_keys (
    host TEXT NOT NULL
        REFERENCES "v2".federation_servers(host)
        ON DELETE CASCADE,
    key_id TEXT NOT NULL,
    public_key BYTEA NOT NULL
        CHECK (octet_length(public_key) = 32),
    valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (host, key_id),
    CHECK (valid_until IS NULL OR valid_until > valid_from)
);

CREATE INDEX IF NOT EXISTS federation_server_keys_active_idx
ON "v2".federation_server_keys (host, key_id)
WHERE revoked_at IS NULL;

-- federated actors
CREATE TABLE IF NOT EXISTS "v2".actors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_uri TEXT NOT NULL UNIQUE,
    host TEXT NOT NULL,
    username TEXT NOT NULL,
    display_name TEXT,
    actor_type TEXT NOT NULL DEFAULT 'user'
        CHECK (actor_type IN ('user', 'bot', 'service')),
    local_user_id UUID UNIQUE
        REFERENCES public.users(id)
        ON DELETE RESTRICT,
    public_key BYTEA,
    key_id TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT actors_host_lowercase
        CHECK (host = LOWER(host)),

    CONSTRAINT actors_local_identity
        CHECK (
            (local_user_id IS NOT NULL AND public_key IS NULL AND key_id IS NULL)
            OR
            (local_user_id IS NULL)
        )
);

CREATE INDEX IF NOT EXISTS actors_host_username_idx
ON "v2".actors (host, username);

CREATE INDEX IF NOT EXISTS actors_local_user_id_idx
ON "v2".actors (local_user_id)
WHERE local_user_id IS NOT NULL;

-- federation replay protection
CREATE TABLE IF NOT EXISTS "v2".federation_seen_requests (
    origin TEXT NOT NULL,
    request_id UUID NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (origin, request_id)
);

CREATE INDEX IF NOT EXISTS federation_seen_requests_received_at_idx
ON "v2".federation_seen_requests (received_at);

-- federation inbox
CREATE TABLE IF NOT EXISTS "v2".federation_inbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    origin TEXT NOT NULL,
    request_id UUID NOT NULL,
    key_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    signature BYTEA NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    processing_error TEXT,
    UNIQUE (origin, request_id)
);

CREATE INDEX IF NOT EXISTS federation_inbox_unprocessed_idx
ON "v2".federation_inbox (received_at)
WHERE processed_at IS NULL;

-- federation outbox
CREATE TABLE IF NOT EXISTS "v2".federation_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    object_uri TEXT NOT NULL,
    actor_uri TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    CHECK (attempts >= 0)
);

CREATE INDEX IF NOT EXISTS federation_outbox_pending_idx
ON "v2".federation_outbox (created_at)
WHERE published_at IS NULL;

-- spaces
CREATE TABLE IF NOT EXISTS "v2".spaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    federation_uri TEXT NOT NULL UNIQUE,
    origin_host TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    owner_actor_id UUID NOT NULL
        REFERENCES "v2".actors(id)
        ON DELETE RESTRICT,
    visibility TEXT NOT NULL DEFAULT 'private'
        CHECK (visibility IN ('private', 'public')),
    revision BIGINT NOT NULL DEFAULT 1,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (revision > 0),
    CHECK (origin_host = LOWER(origin_host))
);

CREATE INDEX IF NOT EXISTS spaces_origin_host_idx
ON "v2".spaces (origin_host);

CREATE INDEX IF NOT EXISTS spaces_owner_actor_id_idx
ON "v2".spaces (owner_actor_id);

-- space memberships
CREATE TABLE IF NOT EXISTS "v2".space_members (
    space_id UUID NOT NULL
        REFERENCES "v2".spaces(id)
        ON DELETE CASCADE,
    actor_id UUID NOT NULL
        REFERENCES "v2".actors(id)
        ON DELETE RESTRICT,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    membership_status TEXT NOT NULL DEFAULT 'active'
        CHECK (membership_status IN ('active', 'pending', 'suspended')),
    PRIMARY KEY (space_id, actor_id)
);

CREATE INDEX IF NOT EXISTS space_members_actor_id_idx
ON "v2".space_members (actor_id);

-- custom roles
CREATE TABLE IF NOT EXISTS "v2".space_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    space_id UUID NOT NULL
        REFERENCES "v2".spaces(id)
        ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    color TEXT,
    position INTEGER NOT NULL DEFAULT 0,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_by_actor_id UUID
        REFERENCES "v2".actors(id)
        ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (space_id, id),
    UNIQUE (space_id, name)
);

CREATE UNIQUE INDEX IF NOT EXISTS space_roles_one_default_idx
ON "v2".space_roles (space_id)
WHERE is_default = TRUE;

CREATE INDEX IF NOT EXISTS space_roles_space_position_idx
ON "v2".space_roles (space_id, position);

-- available permissions
CREATE TABLE IF NOT EXISTS "v2".permissions (
    id TEXT PRIMARY KEY,
    description TEXT NOT NULL
);

INSERT INTO "v2".permissions (id, description)
VALUES
    ('messages.delete', 'Delete messages'),
    ('members.kick', 'Remove members from a space'),
    ('members.ban', 'Ban members from a space'),
    ('members.manage_roles', 'Manage member roles'),
    ('roles.manage', 'Create and manage roles'),
    ('invites.create', 'Create space invitations'),
    ('invites.manage', 'Manage space invitations'),
    ('channels.create', 'Create channels and subchannels'),
    ('channels.manage', 'Manage channels and subchannels'),
    ('channels.manage_access', 'Manage channel access'),
    ('space.manage', 'Manage space settings')
ON CONFLICT (id) DO NOTHING;

-- permissions granted to roles
CREATE TABLE IF NOT EXISTS "v2".space_role_permissions (
    space_id UUID NOT NULL,
    role_id UUID NOT NULL,
    permission_id TEXT NOT NULL
        REFERENCES "v2".permissions(id)
        ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (space_id, role_id)
        REFERENCES "v2".space_roles(space_id, id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS space_role_permissions_permission_idx
ON "v2".space_role_permissions (permission_id);

-- roles assigned to members
CREATE TABLE IF NOT EXISTS "v2".space_member_roles (
    space_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    role_id UUID NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by_actor_id UUID
        REFERENCES "v2".actors(id)
        ON DELETE SET NULL,
    PRIMARY KEY (space_id, actor_id, role_id),
    FOREIGN KEY (space_id, actor_id)
        REFERENCES "v2".space_members(space_id, actor_id)
        ON DELETE CASCADE,
    FOREIGN KEY (space_id, role_id)
        REFERENCES "v2".space_roles(space_id, id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS space_member_roles_role_idx
ON "v2".space_member_roles (space_id, role_id);

-- space invitations
CREATE TABLE IF NOT EXISTS "v2".space_invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    space_id UUID NOT NULL
        REFERENCES "v2".spaces(id)
        ON DELETE CASCADE,
    code_hash TEXT NOT NULL UNIQUE,
    role_id UUID,
    created_by_actor_id UUID NOT NULL
        REFERENCES "v2".actors(id)
        ON DELETE RESTRICT,
    max_uses INTEGER,
    uses_count INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (max_uses IS NULL OR max_uses > 0),
    CHECK (uses_count >= 0),
    FOREIGN KEY (space_id, role_id)
        REFERENCES "v2".space_roles(space_id, id)
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS space_invites_space_id_idx
ON "v2".space_invites (space_id);

-- channels
CREATE TABLE IF NOT EXISTS "v2".channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    space_id UUID NOT NULL
        REFERENCES "v2".spaces(id)
        ON DELETE CASCADE,
    parent_id UUID,
    name TEXT NOT NULL,
    description TEXT,
    position INTEGER NOT NULL DEFAULT 0,
    access_mode TEXT NOT NULL DEFAULT 'inherited'
        CHECK (access_mode IN ('inherited', 'restricted', 'public')),
    created_by_actor_id UUID NOT NULL
        REFERENCES "v2".actors(id)
        ON DELETE RESTRICT,
    is_archived BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (space_id, id),
    FOREIGN KEY (space_id, parent_id)
        REFERENCES "v2".channels(space_id, id)
        ON DELETE CASCADE,
    CHECK (parent_id IS NULL OR parent_id <> id)
);

CREATE INDEX IF NOT EXISTS channels_space_parent_position_idx
ON "v2".channels (space_id, parent_id, position);

CREATE INDEX IF NOT EXISTS channels_parent_id_idx
ON "v2".channels (parent_id);

-- channel member access
CREATE TABLE IF NOT EXISTS "v2".channel_member_access (
    space_id UUID NOT NULL,
    channel_id UUID NOT NULL,
    actor_id UUID NOT NULL,
    access_level TEXT NOT NULL
        CHECK (access_level IN ('allow', 'deny')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, actor_id),
    FOREIGN KEY (space_id, channel_id)
        REFERENCES "v2".channels(space_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (space_id, actor_id)
        REFERENCES "v2".space_members(space_id, actor_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS channel_member_access_actor_idx
ON "v2".channel_member_access (space_id, actor_id);

-- channel role access
CREATE TABLE IF NOT EXISTS "v2".channel_role_access (
    space_id UUID NOT NULL,
    channel_id UUID NOT NULL,
    role_id UUID NOT NULL,
    access_level TEXT NOT NULL
        CHECK (access_level IN ('allow', 'deny')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, role_id),
    FOREIGN KEY (space_id, channel_id)
        REFERENCES "v2".channels(space_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (space_id, role_id)
        REFERENCES "v2".space_roles(space_id, id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS channel_role_access_role_idx
ON "v2".channel_role_access (space_id, role_id);

create table if not exists "v2".messages (
    id uuid primary key,
    channel_id uuid not null references "v2".channels(id) on delete cascade,
    author_actor_id uuid not null references "v2".actors(id),
    content text not null,
    created_at timestamptz not null default now(),
    edited_at timestamptz,
    deleted_at timestamptz
);

create index if not exists messages_channel_created_idx
on "v2".messages (channel_id, created_at desc, id desc);