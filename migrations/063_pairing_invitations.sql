-- R2J.3: tightly scoped, short-lived one-use *proposal* invitations.
-- Redeeming one never approves or enrolls an agent, grants no capabilities.
BEGIN;
CREATE TABLE IF NOT EXISTS lr_pairing_invitations (
 organization_id TEXT NOT NULL,
 invite_id TEXT NOT NULL CHECK(length(invite_id) BETWEEN 1 AND 128),
 site_id TEXT NOT NULL,
 admin_id TEXT NOT NULL,
 secret_hash BYTEA NOT NULL CHECK(octet_length(secret_hash)=32),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 expires_at TIMESTAMPTZ NOT NULL,
 consumed_at TIMESTAMPTZ,
 request_id TEXT,
 PRIMARY KEY(organization_id,invite_id),
 UNIQUE(secret_hash),
 FOREIGN KEY(organization_id,site_id) REFERENCES lr_sites(organization_id,site_id),
 FOREIGN KEY(organization_id,admin_id) REFERENCES lr_admin_keys(organization_id,admin_id),
 FOREIGN KEY(organization_id,request_id) REFERENCES lr_pairings(organization_id,request_id),
 CHECK ((consumed_at IS NULL AND request_id IS NULL) OR
        (consumed_at IS NOT NULL AND request_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS lr_invitation_active_lookup
 ON lr_pairing_invitations(organization_id,expires_at)
 WHERE consumed_at IS NULL;
CREATE TABLE IF NOT EXISTS lr_pairing_invitation_audit (
 event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 organization_id TEXT NOT NULL,
 invite_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('ISSUED','REDEEMED')),
 occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 FOREIGN KEY(organization_id,invite_id) REFERENCES lr_pairing_invitations(organization_id,invite_id)
);
COMMIT;
