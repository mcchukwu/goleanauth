ALTER TABLE authorization_codes
    DROP COLUMN IF EXISTS code_challenge,
    DROP COLUMN IF EXISTS code_challenge_method;