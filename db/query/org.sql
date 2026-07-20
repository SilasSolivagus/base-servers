-- name: CreateOrg :one
INSERT INTO organizations (name) VALUES ($1) RETURNING id, name, COALESCE(parent_id::text, '') AS parent_id;

-- name: GetOrg :one
SELECT id, name, COALESCE(parent_id::text, '') AS parent_id FROM organizations WHERE id = $1;

-- name: CreateTeam :one
INSERT INTO teams (org_id, name) VALUES ($1, $2) RETURNING id, org_id, name;

-- name: AddMember :exec
INSERT INTO memberships (principal_id, org_id) VALUES ($1, $2)
ON CONFLICT (principal_id, org_id) DO NOTHING;

-- name: AddTeamMember :exec
INSERT INTO team_memberships (principal_id, team_id) VALUES ($1, $2)
ON CONFLICT (principal_id, team_id) DO NOTHING;
