CREATE TABLE IF NOT EXISTS trusted_federation_servers (
  instance_id UUID PRIMARY KEY,
  origin TEXT NOT NULL UNIQUE,
  public_key JSONB NOT NULL,
  trusted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT trusted_federation_origin_https
    CHECK (origin ~ '^https://[^/]+$'),

  CONSTRAINT trusted_federation_public_key_format
    CHECK (
      public_key->>'kty' = 'OKP'
      AND public_key->>'crv' = 'Ed25519'
      AND public_key ? 'x'
      AND NOT (public_key ? 'd')
    )
);
