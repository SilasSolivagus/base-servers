-- +goose Up
CREATE TABLE signing_keys (
    kid          TEXT PRIMARY KEY,
    alg          TEXT NOT NULL DEFAULT 'ES256',
    private_enc  BYTEA NOT NULL,           -- AES-256-GCM 信封密文(nonce||ct)
    state        TEXT NOT NULL DEFAULT 'active',  -- active | retiring
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    retire_after TIMESTAMPTZ
);
-- 至多一把 active 键:分区唯一索引强制;retiring 键不受限
CREATE UNIQUE INDEX signing_keys_single_active ON signing_keys (state) WHERE state = 'active';

-- +goose Down
DROP TABLE signing_keys;
