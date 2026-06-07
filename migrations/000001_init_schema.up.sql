-- INSTALL EXTENTIONS IF NOT EXISTS
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- WRITE SYSTEM WIDE FUNCTIONS
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- USER TABLE
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    email           TEXT UNIQUE,
    phone           TEXT UNIQUE,

    password_hash   TEXT NOT NULL,

    first_name      TEXT,
    last_name       TEXT,
    date_of_birth   TIMESTAMP,

    status          TEXT NOT NULL DEFAULT 'active',
    -- active | suspended | deleted

    email_verified  BOOLEAN DEFAULT FALSE,
    phone_verified  BOOLEAN DEFAULT FALSE,

    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW(),

    CHECK (email IS NOT NULL OR phone IS NOT NULL)
);

-- CREATE USER TRIGGERS
CREATE TRIGGER users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- CREATE USER INDEXES FOR EMAIL AND PHONE
CREATE INDEX idx_users_email
ON users(email);
CREATE INDEX idx_users_phone
ON users(phone);

-- SESSIONS (auth + device tracking)
CREATE TABLE sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    refresh_token_hash  TEXT UNIQUE NOT NULL,

    user_agent          TEXT,
    ip_address          TEXT,

    revoked             BOOLEAN DEFAULT FALSE,
    revoked_at          TIMESTAMP,

    expires_at          TIMESTAMP NOT NULL,
    created_at          TIMESTAMP NOT NULL DEFAULT NOW()
);

-- SESSION INDEXES
CREATE INDEX idx_sessions_user_id
ON sessions(user_id);

-- AUDIT LOGS (enterprise traceability)
CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,

    action          TEXT NOT NULL,
    -- e.g. "user.created"

    entity_type     TEXT,
    entity_id       UUID,

    metadata        JSONB,

    ip_address      TEXT,
    user_agent      TEXT,

    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

-- AUDIT LOG INDEXES
CREATE INDEX idx_audit_logs_user_created
ON audit_logs(user_id, created_at);
