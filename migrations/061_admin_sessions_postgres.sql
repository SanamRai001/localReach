-- R2H.3 signed administrator login session foundation.
-- Tokens and challenges are stored only as SHA-256 hashes.
BEGIN;

CREATE TABLE IF NOT EXISTS lr_admin_login_challenges (
 organization_id TEXT NOT NULL,
 admin_id TEXT NOT NULL,
 nonce_hash BYTEA NOT NULL CHECK(octet_length(nonce_hash)=32),
 expires_at TIMESTAMPTZ NOT NULL,
 consumed_at TIMESTAMPTZ,
 PRIMARY KEY(organization_id,admin_id),
 FOREIGN KEY (organization_id,admin_id)
   REFERENCES lr_admin_keys(organization_id,admin_id)
);
CREATE TABLE IF NOT EXISTS lr_admin_sessions (
 organization_id TEXT NOT NULL,
 admin_id TEXT NOT NULL,
 session_hash BYTEA NOT NULL CHECK(octet_length(session_hash)=32),
 issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 expires_at TIMESTAMPTZ NOT NULL,
 revoked_at TIMESTAMPTZ,
 PRIMARY KEY(organization_id,session_hash),
 FOREIGN KEY (organization_id,admin_id)
   REFERENCES lr_admin_keys(organization_id,admin_id)
);
CREATE INDEX IF NOT EXISTS lr_admin_sessions_member ON lr_admin_sessions
 (organization_id,admin_id,expires_at);
CREATE TABLE IF NOT EXISTS lr_admin_login_audit (
 event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 organization_id TEXT NOT NULL,
 admin_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('CHALLENGE','LOGIN','LOGOUT')),
 occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 FOREIGN KEY (organization_id,admin_id)
   REFERENCES lr_admin_keys(organization_id,admin_id)
);
COMMIT;
