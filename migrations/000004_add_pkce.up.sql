-- PKCE (RFC 7636): store the code challenge for the authorization code flow.
-- Nullable so pre-existing codes without a challenge remain valid.
ALTER TABLE authorization_codes
    ADD COLUMN code_challenge TEXT,
    ADD COLUMN code_challenge_method TEXT;