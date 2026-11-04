BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Users
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(30) NOT NULL,
    host TEXT,
    email VARCHAR(254),
    email_verified_at TIMESTAMPTZ,
    password_hash TEXT,
    public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT users_host_lowercase
        CHECK (host IS NULL OR host = LOWER(host))
);

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

-- spaces
CREATE TABLE IF NOT EXISTS "v2".spaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    owner_id UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    visibility TEXT NOT NULL DEFAULT 'private'
        CHECK (visibility IN ('private', 'public')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS spaces_owner_id_idx
ON "v2".spaces (owner_id);

-- space memberships
CREATE TABLE IF NOT EXISTS "v2".space_members (
    space_id UUID NOT NULL REFERENCES "v2".spaces(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (space_id, user_id)
);

CREATE INDEX IF NOT EXISTS space_members_user_id_idx
ON "v2".space_members (user_id);

-- custom roles
CREATE TABLE IF NOT EXISTS "v2".space_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    space_id UUID NOT NULL REFERENCES "v2".spaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    color TEXT,
    position INTEGER NOT NULL DEFAULT 0,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
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
    ('chat.create', 'Create channels and subchannels')
ON CONFLICT (id) DO NOTHING;

-- permissions granted to roles
CREATE TABLE IF NOT EXISTS "v2".space_role_permissions (
    space_id UUID NOT NULL,
    role_id UUID NOT NULL,
    permission_id TEXT NOT NULL REFERENCES "v2".permissions(id) ON DELETE CASCADE,
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
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    PRIMARY KEY (space_id, user_id, role_id),
    FOREIGN KEY (space_id, user_id)
        REFERENCES "v2".space_members(space_id, user_id)
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
    space_id UUID NOT NULL REFERENCES "v2".spaces(id) ON DELETE CASCADE,
    role_id UUID,
    created_by UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    max_uses INTEGER,
    uses_count INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (max_uses IS NULL OR max_uses > 0),
    CHECK (uses_count >= 0),
    FOREIGN KEY (space_id, role_id)
        REFERENCES "v2".space_roles(space_id, id)
        ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS space_invites_space_id_idx
ON "v2".space_invites (space_id);

-- channels
CREATE TABLE IF NOT EXISTS "v2".channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    space_id UUID NOT NULL REFERENCES "v2".spaces(id) ON DELETE CASCADE,
    parent_id UUID,
    name TEXT NOT NULL,
    description TEXT,
    position INTEGER NOT NULL DEFAULT 0,
    access_mode TEXT NOT NULL DEFAULT 'inherited'
        CHECK (access_mode IN ('inherited', 'restricted', 'public')),
    created_by UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
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
    user_id UUID NOT NULL,
    access_level TEXT NOT NULL
        CHECK (access_level IN ('allow', 'deny')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, user_id),
    FOREIGN KEY (space_id, channel_id)
        REFERENCES "v2".channels(space_id, id)
        ON DELETE CASCADE,
    FOREIGN KEY (space_id, user_id)
        REFERENCES "v2".space_members(space_id, user_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS channel_member_access_user_idx
ON "v2".channel_member_access (space_id, user_id);

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

COMMIT;