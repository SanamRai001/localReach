-- R2J.5: one active, expiring transport lease per enrolled agent.
-- No devices or command authorization are represented by this schema.
BEGIN;
CREATE TABLE IF NOT EXISTS lr_agent_connections (
 organization_id TEXT NOT NULL,
 agent_id TEXT NOT NULL,
 session_id TEXT NOT NULL CHECK(length(session_id) BETWEEN 16 AND 128),
 started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 expires_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY (organization_id,agent_id),
 FOREIGN KEY (organization_id,agent_id) REFERENCES lr_agents(organization_id,agent_id)
);
CREATE INDEX IF NOT EXISTS lr_agent_connections_expiry ON lr_agent_connections(expires_at);
CREATE TABLE IF NOT EXISTS lr_agent_connection_audit (
 event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 organization_id TEXT NOT NULL,
 agent_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('OPEN','CLOSE')),
 happened_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 FOREIGN KEY(organization_id,agent_id) REFERENCES lr_agents(organization_id,agent_id)
);
COMMIT;
