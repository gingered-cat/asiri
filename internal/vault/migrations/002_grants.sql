CREATE TABLE requests (
  id         TEXT    PRIMARY KEY,
  client_id  TEXT    NOT NULL,
  item_id    TEXT    NOT NULL,
  ref        TEXT    NOT NULL,
  bin_path   TEXT    NOT NULL,
  bin_sha256 TEXT    NOT NULL,
  argv       TEXT    NOT NULL,
  cwd        TEXT    NOT NULL,
  reason     TEXT    NOT NULL,
  status     TEXT    NOT NULL,
  decision   TEXT    NOT NULL DEFAULT '',
  method     TEXT    NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  decided_at INTEGER
);
CREATE INDEX requests_pending ON requests (status, created_at);

-- uses_left is 1 for a once-grant and NULL for a timed grant.
CREATE TABLE grants (
  id         TEXT    PRIMARY KEY,
  request_id TEXT    NOT NULL UNIQUE,
  client_id  TEXT    NOT NULL,
  item_id    TEXT    NOT NULL,
  ref        TEXT    NOT NULL,
  bin_path   TEXT    NOT NULL,
  bin_sha256 TEXT    NOT NULL,
  decision   TEXT    NOT NULL,
  method     TEXT    NOT NULL,
  uses_left  INTEGER,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX grants_reuse ON grants (client_id, item_id, bin_sha256, expires_at);
