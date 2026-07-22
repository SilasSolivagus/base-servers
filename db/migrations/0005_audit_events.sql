-- +goose Up
CREATE TABLE audit_events (
    chain        TEXT   NOT NULL,        -- org_id 或 'system'
    seq          BIGINT NOT NULL,        -- 该链自增,从 1
    ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id     TEXT   NOT NULL DEFAULT '',
    actor_type   TEXT   NOT NULL DEFAULT '',
    system_admin BOOLEAN NOT NULL DEFAULT false,
    action       TEXT   NOT NULL,
    target_type  TEXT   NOT NULL DEFAULT '',
    target_id    TEXT   NOT NULL DEFAULT '',
    org_id       TEXT   NOT NULL DEFAULT '',
    outcome      TEXT   NOT NULL,
    detail       JSONB  NOT NULL DEFAULT '{}',
    prev_hash    BYTEA  NOT NULL,
    hash         BYTEA  NOT NULL,
    PRIMARY KEY (chain, seq)
);
CREATE INDEX audit_events_org_ts ON audit_events (org_id, ts DESC);
CREATE INDEX audit_events_actor  ON audit_events (actor_id);
CREATE INDEX audit_events_action ON audit_events (action);

-- 只追加不可变:撤销 PUBLIC 的改/删权限(design §4.3)。注意:表 owner / superuser
-- 天然绕过该撤销,所以在当前"应用以 owner 角色 base 连库"的部署下这条是防御纵深、
-- 尚未生效;真正的"应用角色无 UPDATE/DELETE"需引入最小权限非-owner 角色(见 §8 跟进项)。
-- 与体系结构无关的篡改验真由每租户哈希链 Verify 兜底(即便 superuser 直改也可检出)。
REVOKE UPDATE, DELETE ON audit_events FROM PUBLIC;

-- +goose Down
DROP TABLE audit_events;
