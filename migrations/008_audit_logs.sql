CREATE TABLE audit_logs (
  id               bigserial PRIMARY KEY,
  org_id           uuid REFERENCES organizations(id) ON DELETE SET NULL,
  actor_user_id    uuid REFERENCES users(id) ON DELETE SET NULL,
  actor_api_key_id uuid,
  action           text NOT NULL,
  target_type      text,
  target_id        text,
  metadata         jsonb NOT NULL DEFAULT '{}'::jsonb,
  request_id       text,
  ip               text,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_org_created_idx ON audit_logs (org_id, created_at DESC);
CREATE INDEX audit_actor_created_idx ON audit_logs (actor_user_id, created_at DESC);
CREATE INDEX audit_action_idx ON audit_logs (action);