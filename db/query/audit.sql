-- name: AuditChainHead :one
SELECT seq, hash FROM audit_events WHERE chain = $1 ORDER BY seq DESC LIMIT 1;

-- name: InsertAuditEvent :exec
INSERT INTO audit_events
  (chain, seq, ts, actor_id, actor_type, system_admin, action, target_type, target_id, org_id, outcome, detail, prev_hash, hash)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14);

-- name: ScanAuditChain :many
SELECT seq, ts, actor_id, actor_type, system_admin, action, target_type, target_id, org_id, outcome, detail, prev_hash, hash
FROM audit_events WHERE chain = $1 ORDER BY seq;

-- name: ListAuditEvents :many
SELECT seq, ts, actor_id, actor_type, system_admin, action, target_type, target_id, org_id, outcome, detail
FROM audit_events
WHERE ($1::text = '' OR org_id = $1)
  AND ($2::text = '' OR actor_id = $2)
  AND ($3::text = '' OR action = $3)
  AND ($4::text = '' OR outcome = $4)
  AND ts >= $5 AND ts <= $6
  AND seq > $7
ORDER BY ts DESC, seq DESC
LIMIT $8;
