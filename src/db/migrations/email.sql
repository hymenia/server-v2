BEGIN;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email VARCHAR(254),
    ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_unique
    ON users (LOWER(email))
    WHERE email IS NOT NULL;

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS email_verification_tokens_user_id_idx
    ON email_verification_tokens (user_id);

CREATE INDEX IF NOT EXISTS email_verification_tokens_expires_at_idx
    ON email_verification_tokens (expires_at);

COMMIT;
