-- WP5 (GHSA-fj5g-j4mv-7m5g): make the device grant's consented scope real, and
-- make claim-code revocation reach the tokens the claim code produced.
--
-- scope: the device grant validates a requested scope, persists it on
-- oauth_device_codes, and shows it to the user on the approval page — then
-- discarded it at issuance, so every device received a full-privilege user
-- token. Carrying the scope on the refresh token is what lets it survive
-- rotation: without it, the first refresh would silently widen the grant back
-- to full privilege.
--
-- claim_code_id: revoking a claim code stops the paired device at its next
-- poll, but tokens it had already been issued kept working for the refresh
-- token's full 30-day sliding window. Recording which claim code a token family
-- came from is what makes the revocation reach them.
--
-- Both columns are additive with defaults, so existing rows keep working: an
-- empty scope means "no scope restriction", which is the pre-migration
-- behaviour, and a NULL claim_code_id means the token did not come from a
-- claim code.
ALTER TABLE refresh_tokens ADD COLUMN scope         TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN claim_code_id TEXT;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_claim_code_id ON refresh_tokens(claim_code_id);
