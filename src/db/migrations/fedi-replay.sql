CREATE TABLE IF NOT EXISTS federation_seen_requests (
  origin TEXT NOT NULL,
  request_id UUID NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (origin, request_id)
);

CREATE INDEX IF NOT EXISTS federation_seen_requests_received_at_idx
ON federation_seen_requests (received_at);
