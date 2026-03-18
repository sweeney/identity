-- Add flag columns to webauthn_credentials for databases that ran migration 003
-- before these columns were added. ALTER TABLE ADD COLUMN errors for columns that
-- already exist are tolerated by the migration runner.
ALTER TABLE webauthn_credentials ADD COLUMN backup_eligible INTEGER NOT NULL DEFAULT 0 CHECK(backup_eligible IN (0, 1));
ALTER TABLE webauthn_credentials ADD COLUMN backup_state INTEGER NOT NULL DEFAULT 0 CHECK(backup_state IN (0, 1));
ALTER TABLE webauthn_credentials ADD COLUMN user_present INTEGER NOT NULL DEFAULT 1 CHECK(user_present IN (0, 1));
ALTER TABLE webauthn_credentials ADD COLUMN user_verified INTEGER NOT NULL DEFAULT 0 CHECK(user_verified IN (0, 1));
