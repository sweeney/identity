-- Make `aud` multi-valued, so a client whose tokens are used against several
-- services can say so.
--
-- RFC 7519 §4.1.3 defines aud as an array (or a bare string in the one-audience
-- case), and this is the standard way to express "this token is for these
-- recipients". The single-string column could not, which forced the choice
-- between naming one service (and breaking the others) or naming none (and
-- losing the boundary everywhere).
--
-- Stored as a JSON array, matching how this table already holds redirect_uris,
-- grant_types and scopes — `audience` was the odd one out.
--
-- The backfill is exact: an empty audience becomes [], a single value becomes a
-- one-element array. Nothing changes on the wire, because golang-jwt already
-- marshals a one-element ClaimStrings as ["x"].
ALTER TABLE oauth_clients ADD COLUMN audiences TEXT NOT NULL DEFAULT '[]';
UPDATE oauth_clients
   SET audiences = CASE WHEN audience = '' THEN '[]' ELSE json_array(audience) END;

-- Refresh tokens carry the audience forward across rotation, so they need the
-- same shape — otherwise a multi-audience grant would collapse to one value on
-- its first refresh.
ALTER TABLE refresh_tokens ADD COLUMN audiences TEXT NOT NULL DEFAULT '[]';
UPDATE refresh_tokens
   SET audiences = CASE WHEN audience = '' THEN '[]' ELSE json_array(audience) END;
