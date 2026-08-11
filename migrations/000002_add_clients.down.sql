DROP INDEX IF EXISTS idx_sessions_client_id;

ALTER TABLE sessions
    DROP COLUMN IF EXISTS client_id,
    DROP COLUMN IF EXISTS scope;

DROP TABLE IF EXISTS clients;