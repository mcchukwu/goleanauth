-- REGISTERED APPLICATIONS (API clients)
CREATE TABLE clients (
    client_id           TEXT PRIMARY KEY, -- public identifier
    client_secret_hash  TEXT NOT NULL,    -- SHA-256 of the client secret
    name                TEXT NOT NULL,
    scope               TEXT NOT NULL DEFAULT '',
    active              BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- SESSIONS: allow binding a session to a client (machine tokens)
-- and record the granted scope for user sessions.
ALTER TABLE sessions
    ADD COLUMN client_id TEXT REFERENCES clients(client_id) ON DELETE SET NULL,
    ADD COLUMN scope TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_sessions_client_id ON sessions(client_id);