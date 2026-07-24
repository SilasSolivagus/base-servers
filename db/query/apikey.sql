-- name: InsertApiKey :exec
INSERT INTO api_keys (key_id, principal_id, org_id, name, hash, read_only, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetApiKey :one
SELECT key_id, principal_id, org_id, name, hash, hash_version, read_only, revoked, created_at, expires_at, last_used_at
FROM api_keys WHERE key_id = $1;

-- name: ListApiKeysByPrincipal :many
SELECT key_id, principal_id, org_id, name, hash, hash_version, read_only, revoked, created_at, expires_at, last_used_at
FROM api_keys
WHERE principal_id = $1
  AND ($2::timestamptz IS NULL OR created_at < $2)
ORDER BY created_at DESC, key_id DESC
LIMIT $3;

-- name: RevokeApiKey :one
UPDATE api_keys SET revoked = true WHERE key_id = $1
RETURNING key_id, principal_id, org_id, name, hash, hash_version, read_only, revoked, created_at, expires_at, last_used_at;

-- name: TouchApiKeyLastUsed :exec
UPDATE api_keys SET last_used_at = now()
WHERE key_id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');

-- name: CountActiveApiKeys :one
SELECT count(*) FROM api_keys
WHERE principal_id = $1 AND NOT revoked AND (expires_at IS NULL OR expires_at > now());
