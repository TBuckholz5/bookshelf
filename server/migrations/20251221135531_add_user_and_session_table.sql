-- +goose Up
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    oauth_provider_id VARCHAR(255) UNIQUE NOT NULL,
    oauth_provider_name VARCHAR(50) NOT NULL,

    email VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255),

    encrypted_access_token BYTEA,
    encrypted_refresh_token BYTEA,

    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMPTZ,

    CONSTRAINT unique_oauth_identity UNIQUE (oauth_provider_name, oauth_provider_id)
);

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    is_revoked BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);

-- +goose Down
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;

