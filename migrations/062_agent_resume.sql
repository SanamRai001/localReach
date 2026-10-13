-- R2I.3: challenge/response for a previously enrolled agent after restart.
-- Scoped, single-use, no automatic device grants or local private-key storage.
BEGIN;
CREATE TABLE IF NOT EXISTS lr_agent_resume_challenges (
  organization_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  nonce_hash BYTEA NOT NULL CHECK(octet_length(nonce_hash)=32),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  PRIMARY KEY (organization_id,agent_id),
  FOREIGN KEY (organization_id,agent_id) REFERENCES lr_agents(organization_id,agent_id)
);
CREATE TABLE IF NOT EXISTS lr_agent_identity_audit (
  event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  organization_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK(event_type IN ('RESUME_VERIFIED')),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (organization_id,agent_id) REFERENCES lr_agents(organization_id,agent_id)
);
COMMIT;
