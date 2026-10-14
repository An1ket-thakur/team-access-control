CREATE TABLE users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         text NOT NULL,
  name          text NOT NULL,
  password_hash text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  deleted_at    timestamptz
);

-- Emails are stored lower-cased. Uniqueness only applies to live accounts,
-- so a soft-deleted user's address can be reused.
CREATE UNIQUE INDEX users_email_active_uq ON users (email) WHERE deleted_at IS NULL;