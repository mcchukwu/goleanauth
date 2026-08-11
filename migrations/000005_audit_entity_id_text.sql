-- 000005: audit entity_id is TEXT; entities include text-keyed clients as
-- well as UUID users/sessions.
-- +goose Up
ALTER TABLE audit_logs
    ALTER COLUMN entity_id TYPE TEXT USING entity_id::text;

-- +goose Down
ALTER TABLE audit_logs
    ALTER COLUMN entity_id TYPE UUID USING NULL;