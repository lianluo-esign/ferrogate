-- Account credentials belong only to CONTROL_DATA. Never project these into tenant DOs or KV.
CREATE TABLE admin_passkeys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL,
  user_handle TEXT NOT NULL,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT NOT NULL DEFAULT '[]',
  name TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revision INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_admin_passkeys_owner ON admin_passkeys(user_id, tenant_id);

CREATE TABLE admin_passkey_challenges (
  id TEXT PRIMARY KEY,
  challenge TEXT NOT NULL,
  binding TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('register', 'login')),
  user_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX idx_admin_passkey_challenges_expiry ON admin_passkey_challenges(expires_at);

CREATE TABLE admin_passkey_rate_limits (
  bucket TEXT PRIMARY KEY,
  attempts INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX idx_admin_passkey_rate_expiry ON admin_passkey_rate_limits(expires_at);
