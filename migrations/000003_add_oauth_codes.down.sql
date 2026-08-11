DROP TABLE IF EXISTS authorization_codes;

ALTER TABLE clients
    DROP COLUMN IF EXISTS redirect_uris;

ALTER TABLE sessions
    ALTER COLUMN user_id SET NOT NULL;