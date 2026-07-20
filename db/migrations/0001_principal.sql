-- +goose Up
CREATE TABLE principals (
    id                  TEXT PRIMARY KEY,
    type                TEXT NOT NULL CHECK (type IN ('human','service','agent')),
    display_name        TEXT NOT NULL,
    owner_principal_id  TEXT,
    capabilities        TEXT[] NOT NULL DEFAULT '{}',
    purpose             TEXT NOT NULL DEFAULT '',
    on_behalf_of        TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE principals;
