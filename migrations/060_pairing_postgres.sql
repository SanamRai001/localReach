-- R2H.3 experimental PostgreSQL transactional pairing backend.
-- Apply only to a dedicated database. No public listeners or device grants.
BEGIN;

CREATE TABLE IF NOT EXISTS lr_organizations (
  organization_id TEXT PRIMARY KEY CHECK (length(organization_id) BETWEEN 1 AND 128),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','BLOCKED'))
);
CREATE TABLE IF NOT EXISTS lr_sites (
  organization_id TEXT NOT NULL REFERENCES lr_organizations(organization_id),
  site_id TEXT NOT NULL CHECK (length(site_id) BETWEEN 1 AND 128),
  PRIMARY KEY (organization_id,site_id)
);
CREATE TABLE IF NOT EXISTS lr_admin_keys (
  organization_id TEXT NOT NULL REFERENCES lr_organizations(organization_id),
  admin_id TEXT NOT NULL CHECK (length(admin_id) BETWEEN 1 AND 128),
  public_key BYTEA NOT NULL CHECK (octet_length(public_key)=32),
  role TEXT NOT NULL CHECK (role IN ('OWNER','ADMIN','VIEWER')),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','REVOKED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ,
  PRIMARY KEY (organization_id,admin_id),
  UNIQUE (public_key)
);
CREATE TABLE IF NOT EXISTS lr_pairings (
  organization_id TEXT NOT NULL,
  request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 128),
  site_id TEXT NOT NULL,
  public_key BYTEA NOT NULL CHECK (octet_length(public_key)=32),
  status TEXT NOT NULL DEFAULT 'PENDING'
    CHECK (status IN ('PENDING','APPROVED','REJECTED','ENROLLED','REVOKED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  approval_expires_at TIMESTAMPTZ,
  agent_id TEXT UNIQUE,
  enrolled_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  PRIMARY KEY (organization_id,request_id),
  UNIQUE (public_key),
  FOREIGN KEY (organization_id,site_id) REFERENCES lr_sites(organization_id,site_id),
  CHECK (expires_at > created_at),
  CHECK (status <> 'ENROLLED' OR (agent_id IS NOT NULL AND enrolled_at IS NOT NULL)),
  CHECK (status <> 'REVOKED' OR revoked_at IS NOT NULL)
);
CREATE TABLE IF NOT EXISTS lr_decision_nonces (
  organization_id TEXT NOT NULL,
  nonce_hash BYTEA NOT NULL CHECK (octet_length(nonce_hash)=32),
  request_id TEXT NOT NULL,
  admin_id TEXT NOT NULL,
  consumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (organization_id,nonce_hash),
  FOREIGN KEY (organization_id,request_id) REFERENCES lr_pairings(organization_id,request_id),
  FOREIGN KEY (organization_id,admin_id) REFERENCES lr_admin_keys(organization_id,admin_id)
);
CREATE TABLE IF NOT EXISTS lr_pairing_challenges (
  organization_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  nonce_hash BYTEA NOT NULL CHECK (octet_length(nonce_hash)=32),
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  PRIMARY KEY (organization_id,request_id),
  FOREIGN KEY (organization_id,request_id) REFERENCES lr_pairings(organization_id,request_id)
);
CREATE TABLE IF NOT EXISTS lr_agents (
  organization_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  public_key BYTEA NOT NULL CHECK (octet_length(public_key)=32),
  enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ,
  PRIMARY KEY (organization_id,agent_id),
  UNIQUE (organization_id,request_id),
  FOREIGN KEY (organization_id,request_id) REFERENCES lr_pairings(organization_id,request_id)
);
CREATE TABLE IF NOT EXISTS lr_pairing_audit (
  event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  organization_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('SYSTEM','ADMIN','AGENT')),
  actor_id TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('PROPOSE','APPROVE','REJECT','ENROLL','REVOKE')),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (organization_id,request_id) REFERENCES lr_pairings(organization_id,request_id)
);
CREATE INDEX IF NOT EXISTS lr_pairings_status_idx ON lr_pairings(organization_id,status,expires_at);
CREATE INDEX IF NOT EXISTS lr_audit_request_idx ON lr_pairing_audit(organization_id,request_id,event_id);

COMMIT;
