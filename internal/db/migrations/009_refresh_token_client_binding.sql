-- WP4 (GHSA-vrh2-jqhp-4m44): bind refresh tokens to the client they were
-- issued to.
--
-- The refresh_token grant at /oauth/token performed no client authentication
-- and no client binding, so a refresh token leaked from one OAuth client could
-- be redeemed by any other registered client — including one the user never
-- consented to. Recording the issuing client is what lets the grant refuse
-- that.
--
-- Additive with a NULL default: existing tokens have no client and stay
-- redeemable, which is the pre-migration behaviour for tokens issued through
-- the direct API login (which has no client at all).
ALTER TABLE refresh_tokens ADD COLUMN client_id TEXT;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client_id ON refresh_tokens(client_id);
