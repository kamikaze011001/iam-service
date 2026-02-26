CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT UNIQUE NOT NULL,
    display_name  TEXT,
    google_sub    TEXT UNIQUE,
    roles         TEXT[] NOT NULL DEFAULT '{USER}',
    status        TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role    TEXT NOT NULL,
    PRIMARY KEY (user_id, role)
);

CREATE TABLE passkey_credentials (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id    BYTEA UNIQUE NOT NULL,
    public_key_cose  BYTEA NOT NULL,
    sign_counter     BIGINT NOT NULL DEFAULT 0,
    aaguid           UUID,
    display_name     TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at     TIMESTAMPTZ
);
CREATE INDEX idx_passkey_user_id ON passkey_credentials(user_id);

CREATE TABLE audit_logs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type   TEXT NOT NULL,
    user_id      UUID,
    actor_id     UUID,
    ip_address   INET,
    user_agent   TEXT,
    metadata     JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_created  ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_event    ON audit_logs(event_type);
