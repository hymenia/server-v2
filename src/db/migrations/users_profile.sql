-- profile, moderation and bot columns ported from the v1 schema
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS display_name TEXT;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS bio TEXT;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS avatar_url TEXT;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS global_roles TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS moderation_status INTEGER NOT NULL DEFAULT 0;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS moderation_reason TEXT;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS moderation_expires_at TIMESTAMPTZ;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS moderated_by UUID;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS is_bot BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS app_owner_id UUID;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'users_app_owner_id_fkey'
          AND conrelid = 'public.users'::regclass
    ) THEN
        ALTER TABLE public.users
            ADD CONSTRAINT users_app_owner_id_fkey
            FOREIGN KEY (app_owner_id)
            REFERENCES public.users(id)
            ON DELETE CASCADE;
    END IF;
END
$$;
