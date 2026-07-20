-- name: InsertDelegation :one
INSERT INTO delegations (agent_principal_id, delegator_principal_id, org_id, scope, cnf_jkt, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id;

-- name: GetDelegation :one
SELECT id, agent_principal_id, delegator_principal_id, org_id, scope, cnf_jkt, expires_at, revoked
FROM delegations WHERE id = $1;

-- name: RevokeDelegation :execrows
UPDATE delegations SET revoked = true WHERE id = $1;
