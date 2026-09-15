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
-- The backfill clears the legacy column as it goes, so that re-running it
-- matches nothing. That was originally load-bearing: the runner kept no record
-- of what it had applied, so every file ran on every startup, and a bare
-- `UPDATE ... SET audiences = <from audience>` reverted every edit made since
-- the migration — and wiped the column outright for clients created
-- afterwards, whose legacy `audience` is empty. Since #44 the runner records
-- each migration in schema_migrations and never offers it twice, so the guard
-- is belt and braces rather than the only thing between an operator and their
-- configuration.
ALTER TABLE oauth_clients ADD COLUMN audiences TEXT NOT NULL DEFAULT '[]';
UPDATE oauth_clients
   SET audiences = json_array(audience),
       audience  = ''
 WHERE audience <> '';

-- Refresh tokens carry the audience forward across rotation, so they need the
-- same shape — otherwise a multi-audience grant would collapse to one value on
-- its first refresh. Same idempotence rule.
ALTER TABLE refresh_tokens ADD COLUMN audiences TEXT NOT NULL DEFAULT '[]';
UPDATE refresh_tokens
   SET audiences = json_array(audience),
       audience  = ''
 WHERE audience <> '';
