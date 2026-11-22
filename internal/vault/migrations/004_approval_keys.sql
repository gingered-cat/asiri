-- Secure Enclave keys that sign "allow" decisions. While any key here is
-- live, the server refuses an allow without a valid signature by one of them.
CREATE TABLE approval_keys (
  id         TEXT    PRIMARY KEY,
  name       TEXT    NOT NULL,
  client_id  TEXT    NOT NULL,
  public_key BLOB    NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);
