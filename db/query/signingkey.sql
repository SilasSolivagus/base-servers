-- name: InsertSigningKey :exec
INSERT INTO signing_keys (kid, alg, private_enc, state, retire_after)
VALUES ($1, $2, $3, $4, $5);

-- name: GetActiveSigningKey :one
SELECT kid, alg, private_enc, state, retire_after
FROM signing_keys WHERE state = 'active';

-- name: ListLiveSigningKeys :many
SELECT kid, alg, private_enc, state, retire_after
FROM signing_keys WHERE state IN ('active', 'retiring')
ORDER BY created_at;

-- name: DemoteActiveSigningKey :exec
UPDATE signing_keys SET state = 'retiring', retire_after = $1 WHERE state = 'active';

-- name: DeleteExpiredSigningKeys :execrows
DELETE FROM signing_keys WHERE state = 'retiring' AND retire_after < now();
