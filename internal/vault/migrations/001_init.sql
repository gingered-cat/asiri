CREATE TABLE meta (
  k TEXT PRIMARY KEY,
  v BLOB NOT NULL
);

-- One row per item version. id is stable across versions.
CREATE TABLE items (
  id          TEXT    NOT NULL,
  version     INTEGER NOT NULL,
  vault       TEXT    NOT NULL,
  name        TEXT    NOT NULL,
  field       TEXT    NOT NULL,
  kind        TEXT    NOT NULL,
  ciphertext  BLOB    NOT NULL,
  nonce       BLOB    NOT NULL,
  wrapped_dek BLOB    NOT NULL,
  dek_nonce   BLOB    NOT NULL,
  created_at  INTEGER NOT NULL,
  deleted_at  INTEGER,
  PRIMARY KEY (id, version),
  UNIQUE (vault, name, field, version)
);
CREATE INDEX items_ref ON items (vault, name, field, version DESC);

CREATE TABLE policies (
  item_id         TEXT    PRIMARY KEY,
  bins            TEXT    NOT NULL DEFAULT '[]',
  ssh_hosts       TEXT    NOT NULL DEFAULT '[]',
  max_grant       TEXT    NOT NULL DEFAULT '1h',
  reveal_to_agent INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE clients (
  id         TEXT    PRIMARY KEY,
  name       TEXT    NOT NULL UNIQUE,
  role       TEXT    NOT NULL,
  cert_fp    TEXT    UNIQUE,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);

-- Only a hash of the secret part of each code is stored.
CREATE TABLE pair_codes (
  hash       BLOB    PRIMARY KEY,
  name       TEXT    NOT NULL,
  role       TEXT    NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
);

CREATE TABLE audit (
  seq       INTEGER PRIMARY KEY,
  ts        INTEGER NOT NULL,
  client_id TEXT    NOT NULL DEFAULT '',
  event     TEXT    NOT NULL,
  item_id   TEXT    NOT NULL DEFAULT '',
  detail    TEXT    NOT NULL DEFAULT '{}',
  prev_hash BLOB    NOT NULL,
  hash      BLOB    NOT NULL
);
