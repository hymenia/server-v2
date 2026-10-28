BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- users
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(30) NOT NULL,
    password_hash TEXT NOT NULL,
    public_key TEXT NOT NULL
        CHECK (public_key ~ '^[0-9a-f]{64}$'),
    private_key TEXT NOT NULL
        CHECK (private_key ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_unique
    ON users (LOWER(username));

-- sessions
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS sessions_user_id_idx
    ON sessions (user_id);

CREATE INDEX IF NOT EXISTS sessions_expires_at_idx
    ON sessions (expires_at);

COMMIT;
