-- 000004: PKCE (RFC 7636) challenge columns for the authorization code flow.
-- +goose Up
-- PKCE (RFC 7636): store the code challenge for the authorization code flow.
-- Nullable so pre-existing codes without a challenge remain valid.
ALTER TABLE authorization_codes
    ADD COLUMN code_challenge TEXT,
    ADD COLUMN code_challenge_method TEXT;

-- +goose Down
ALTER TABLE authorization_codes
    DROP COLUMN IF EXISTS code_challenge,
    DROP COLUMN IF EXISTS code_challenge_method;