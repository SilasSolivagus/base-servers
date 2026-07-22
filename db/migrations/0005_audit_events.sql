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

-- +goose Down
DROP TABLE audit_events;
