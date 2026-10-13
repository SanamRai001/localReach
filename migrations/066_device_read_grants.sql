-- R2K.1: DEVICE DISCOVERY-ONLY permission policy; NO command execution.
-- mDNS discovery fingerprints are untrusted hints, not hardware identity.
BEGIN;
CREATE TABLE IF NOT EXISTS lr_device_read_grants (
 organization_id TEXT NOT NULL,
 agent_id TEXT NOT NULL,
 site_id TEXT NOT NULL,
 device_fingerprint CHAR(64) NOT NULL CHECK(device_fingerprint ~ '^[0-9a-f]{64}$'),
 capability TEXT NOT NULL CHECK(capability IN ('PRINTER_DISCOVERY_READ','ATTENDANCE_DISCOVERY_READ')),
 status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','REVOKED')),
 approved_by TEXT NOT NULL,
 approved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 expires_at TIMESTAMPTZ NOT NULL,
 revoked_at TIMESTAMPTZ,
 PRIMARY KEY(organization_id,agent_id,device_fingerprint,capability),
 FOREIGN KEY(organization_id,agent_id) REFERENCES lr_agents(organization_id,agent_id),
 FOREIGN KEY(organization_id,site_id) REFERENCES lr_sites(organization_id,site_id),
 FOREIGN KEY(organization_id,approved_by) REFERENCES lr_admin_keys(organization_id,admin_id)
);
CREATE TABLE IF NOT EXISTS lr_device_read_decision_nonces (
 organization_id TEXT NOT NULL,
 nonce_hash BYTEA NOT NULL CHECK(octet_length(nonce_hash)=32),
 inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY(organization_id,nonce_hash),
 FOREIGN KEY(organization_id) REFERENCES lr_organizations(organization_id)
);
CREATE TABLE IF NOT EXISTS lr_device_read_audit (
 event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 organization_id TEXT NOT NULL,
 agent_id TEXT NOT NULL,
 device_fingerprint CHAR(64) NOT NULL,
 capability TEXT NOT NULL,
 admin_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('GRANT','REVOKE')),
 occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 FOREIGN KEY(organization_id,agent_id) REFERENCES lr_agents(organization_id,agent_id)
);
CREATE INDEX IF NOT EXISTS lr_device_read_grants_lookup
 ON lr_device_read_grants(organization_id,agent_id,site_id,status,expires_at);
COMMIT;
