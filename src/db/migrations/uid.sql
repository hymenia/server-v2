-- the file name refers to Universal identification (in terms
-- of federated identity) and not to the UUID data type
ALTER TABLE users
ADD COLUMN public_id UUID NOT NULL DEFAULT gen_random_uuid();

CREATE UNIQUE INDEX users_public_id_unique
ON users (public_id);