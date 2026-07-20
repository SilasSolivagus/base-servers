-- +goose Up
CREATE TABLE delegations (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_principal_id    TEXT NOT NULL,
    delegator_principal_id TEXT NOT NULL,
    org_id                UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scope                 TEXT[] NOT NULL DEFAULT '{}',
    cnf_jkt               TEXT NOT NULL DEFAULT '',
    parent_delegation_id  UUID REFERENCES delegations(id),  -- 预留多跳,v1 不用
    expires_at            TIMESTAMPTZ NOT NULL,
    revoked               BOOLEAN NOT NULL DEFAULT false,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE delegations;
