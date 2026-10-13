-- R2J.4 shared admission accounting for native control-plane endpoints.
-- This is not a replacement for a network WAF / trusted reverse proxy.
BEGIN;
CREATE TABLE IF NOT EXISTS lr_admission_windows (
  action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 100),
  peer_hash BYTEA NOT NULL CHECK (octet_length(peer_hash)=32),
  window_start TIMESTAMPTZ NOT NULL,
  attempts INTEGER NOT NULL CHECK (attempts BETWEEN 1 AND 5),
  PRIMARY KEY (action,peer_hash)
);
CREATE INDEX IF NOT EXISTS lr_admission_windows_age_idx
  ON lr_admission_windows(window_start);
COMMIT;
