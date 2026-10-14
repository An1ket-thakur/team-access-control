CREATE TABLE sessions (
  id                          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_token_hash          text NOT NULL,
  previous_refresh_token_hash text,
  user_agent                  text,
  ip                          text,
  created_at                  timestamptz NOT NULL DEFAULT now(),
  last_used_at                timestamptz NOT NULL DEFAULT now(),
  expires_at                  timestamptz NOT NULL,
  revoked_at                  timestamptz,
  revoked_reason              text
);

CREATE INDEX sessions_user_idx ON sessions (user_id);