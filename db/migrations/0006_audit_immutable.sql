-- +goose Up
-- 只追加不可变(强制层):任何 UPDATE / DELETE / TRUNCATE 都被拒绝,且不依赖角色——
-- 连 owner / superuser `base` 也挡(0005 的 REVOKE 挡不住 owner/superuser)。
-- 唯一的绕过路径是 superuser 显式 `SET session_replication_role = replica`(或 DISABLE
-- TRIGGER)后再改——那正是"拿到 superuser 的越权攻击者",由每租户哈希链 Verify 兜底检出。
CREATE OR REPLACE FUNCTION audit_events_no_mutate() RETURNS trigger
LANGUAGE plpgsql AS $audit$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: % is not permitted', TG_OP;
END;
$audit$;

CREATE TRIGGER audit_events_append_only
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_no_mutate();

CREATE TRIGGER audit_events_no_truncate
    BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_no_mutate();

-- +goose Down
DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events;
DROP FUNCTION IF EXISTS audit_events_no_mutate();
