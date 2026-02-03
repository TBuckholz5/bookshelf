-- +goose Up
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS refresh_token_hash BYTEA NOT NULL;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS refresh_token_expire_at TIMESTAMPTZ NOT NULL;

-- +goose Down
ALTER TABLE sessions DROP COLUMN IF EXISTS refresh_token_hash;
ALTER TABLE sessions DROP COLUMN IF EXISTS refresh_token_expire_at;

