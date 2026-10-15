CREATE TABLE invitations (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email       text NOT NULL,
  role_id     uuid NOT NULL REFERENCES roles(id),
  token_hash  text NOT NULL UNIQUE,
  invited_by  uuid NOT NULL REFERENCES users(id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  accepted_at timestamptz,
  accepted_by uuid REFERENCES users(id),
  revoked_at  timestamptz
);

-- At most one open invitation per email per organization.
CREATE UNIQUE INDEX invitations_pending_uq
  ON invitations (org_id, email) WHERE accepted_at IS NULL AND revoked_at IS NULL;