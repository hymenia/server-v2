-- Universal id for federated identity
ALTER TABLE users
ADD COLUMN IF NOT EXISTS public_id UUID NOT NULL DEFAULT gen_random_uuid();

CREATE UNIQUE INDEX IF NOT EXISTS users_public_id_unique
ON users (public_id);
