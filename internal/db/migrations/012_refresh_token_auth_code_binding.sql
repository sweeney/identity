-- #25: make an authorization-code replay reach the tokens that code produced.
--
-- RFC 6749 §4.1.2: "If an authorization code is used more than once, the
-- authorization server MUST deny the request and SHOULD revoke (when possible)
-- all tokens previously issued based on that authorization code."
--
-- Identity denied the second request and revoked nothing. A code is single-use,
-- so a second presentation means the code leaked — through a referrer header, a
-- proxy log, a shared device. Whoever lost the race may well be the legitimate
-- client, leaving the attacker holding a working refresh token for the full
-- 30-day sliding window, from a code the server already knows was compromised.
--
-- Recording which authorization code a token family came from is what makes the
-- revocation reach them. This mirrors claim_code_id from migration 008 exactly.
--
-- Additive and nullable: a NULL auth_code_id means the token did not come from
-- an authorization code (a direct API login, or a token issued before this
-- migration), which is the pre-migration behaviour.
ALTER TABLE refresh_tokens ADD COLUMN auth_code_id TEXT;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_auth_code_id ON refresh_tokens(auth_code_id);
