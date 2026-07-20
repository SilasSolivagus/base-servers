-- name: InsertPrincipal :exec
INSERT INTO principals (id, type, display_name, owner_principal_id, capabilities, purpose, on_behalf_of)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetPrincipal :one
SELECT id, type, display_name, owner_principal_id, capabilities, purpose, on_behalf_of
FROM principals WHERE id = $1;
