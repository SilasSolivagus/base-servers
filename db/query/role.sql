-- name: CreateRole :one
INSERT INTO roles (org_id, name, permissions) VALUES ($1, $2, $3)
RETURNING id, org_id, name, permissions;

-- name: AssignRole :exec
INSERT INTO role_assignments (principal_id, role_id, scope_type, scope_id)
VALUES ($1, $2, $3, $4)
ON CONFLICT (principal_id, role_id, scope_type, scope_id) DO NOTHING;
