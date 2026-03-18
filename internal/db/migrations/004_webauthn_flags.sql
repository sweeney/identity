-- Add user_present and user_verified columns to webauthn_credentials.
-- These were added to 003_webauthn.sql but existing databases that already ran
-- migration 003 won't have them. ALTER TABLE ADD COLUMN is a no-op if the
-- column already exists (handled by the migration runner's error tolerance).
ALTER TABLE webauthn_credentials ADD COLUMN user_present INTEGER NOT NULL DEFAULT 1 CHECK(user_present IN (0, 1));
ALTER TABLE webauthn_credentials ADD COLUMN user_verified INTEGER NOT NULL DEFAULT 0 CHECK(user_verified IN (0, 1));
