-- name: RegisterOwnership :exec
INSERT INTO ownership (resource_type, resource_id, owner_principal_id, org_id)
VALUES ($1, $2, $3, $4)
ON CONFLICT (resource_type, resource_id)
DO UPDATE SET owner_principal_id = EXCLUDED.owner_principal_id, org_id = EXCLUDED.org_id;

-- name: IsOwner :one
SELECT EXISTS (
    SELECT 1 FROM ownership
    WHERE resource_type = $1 AND resource_id = $2 AND owner_principal_id = $3
) AS is_owner;

-- name: HasPermission :one
SELECT EXISTS (
    SELECT 1
    FROM role_assignments ra
    JOIN roles r ON r.id = ra.role_id
    WHERE ra.principal_id = sqlc.arg(principal_id)
      AND ( sqlc.arg(action)::text = ANY(r.permissions) OR '*' = ANY(r.permissions) )
      AND (
            (ra.scope_type = 'org'  AND ra.scope_id = sqlc.arg(org_id))
         OR (ra.scope_type = 'team' AND ra.scope_id = sqlc.narg(team_id))
      )
) AS allowed;
