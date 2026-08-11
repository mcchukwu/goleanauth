-- 000003: OAuth 2.0 authorization codes, client redirect URIs, and nullable
-- session user_id (machine sessions have no user).
-- +goose Up
-- AUTHORIZATION CODES for the OAuth 2.0 authorization code grant.
-- Codes are single-use, short-lived, and stored as SHA-256 hashes to keep a
-- DB leak from turning into usable tokens.
CREATE TABLE authorization_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    code_hash   TEXT NOT NULL UNIQUE,   -- SHA-256 of the code value

    client_id   TEXT NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    redirect_uri TEXT NOT NULL,         -- bound to prevent code/URI swapping
    scope         TEXT NOT NULL DEFAULT '',

    used        BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_codes_client_user  ON authorization_codes(client_id, user_id);

-- CLIENTS: registered redirect URIs for the authorization code flow.
ALTER TABLE clients
    ADD COLUMN redirect_uris TEXT[] NOT NULL DEFAULT '{}';

-- SESSIONS: client-only (machine) sessions have no user; allow NULL user_id
-- (the base schema declared it NOT NULL, which breaks client_credentials).
ALTER TABLE sessions
    ALTER COLUMN user_id DROP NOT NULL;

-- +goose Down
DROP TABLE IF EXISTS authorization_codes;

ALTER TABLE clients
    DROP COLUMN IF EXISTS redirect_uris;

ALTER TABLE sessions
    ALTER COLUMN user_id SET NOT NULL;