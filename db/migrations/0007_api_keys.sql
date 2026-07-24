-- +goose Up
CREATE TABLE api_keys (
    key_id        TEXT PRIMARY KEY,
    principal_id  TEXT   NOT NULL,
    org_id        TEXT   NOT NULL,
    name          TEXT   NOT NULL DEFAULT '',
    hash          BYTEA  NOT NULL,
    hash_version  SMALLINT NOT NULL DEFAULT 1,
    read_only     BOOLEAN NOT NULL DEFAULT false,
    revoked       BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ
);
CREATE INDEX api_keys_principal ON api_keys (principal_id);
CREATE INDEX api_keys_org       ON api_keys (org_id);

-- +goose Down
DROP TABLE api_keys;
