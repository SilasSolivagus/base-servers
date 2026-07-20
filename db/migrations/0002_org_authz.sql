-- +goose Up
CREATE TABLE organizations (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    parent_id  UUID REFERENCES organizations(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE teams (
    id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name   TEXT NOT NULL
);
CREATE TABLE memberships (
    principal_id TEXT NOT NULL,
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    PRIMARY KEY (principal_id, org_id)
);
CREATE TABLE team_memberships (
    principal_id TEXT NOT NULL,
    team_id      UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    PRIMARY KEY (principal_id, team_id)
);
CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    UNIQUE (org_id, name)
);
CREATE TABLE role_assignments (
    principal_id TEXT NOT NULL,
    role_id      UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope_type   TEXT NOT NULL CHECK (scope_type IN ('org','team')),
    scope_id     UUID NOT NULL,
    PRIMARY KEY (principal_id, role_id, scope_type, scope_id)
);
CREATE TABLE ownership (
    resource_type      TEXT NOT NULL,
    resource_id        TEXT NOT NULL,
    owner_principal_id TEXT NOT NULL,
    org_id             UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    PRIMARY KEY (resource_type, resource_id)
);

-- +goose Down
DROP TABLE ownership;
DROP TABLE role_assignments;
DROP TABLE roles;
DROP TABLE team_memberships;
DROP TABLE memberships;
DROP TABLE teams;
DROP TABLE organizations;
