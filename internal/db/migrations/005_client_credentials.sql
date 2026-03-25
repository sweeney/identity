-- Client credentials support: secret, grant types, scopes, audience
ALTER TABLE oauth_clients ADD COLUMN client_secret_hash      TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_clients ADD COLUMN client_secret_hash_prev TEXT NOT NULL DEFAULT '';
ALTER TABLE oauth_clients ADD COLUMN grant_types             TEXT NOT NULL DEFAULT '["authorization_code"]';
ALTER TABLE oauth_clients ADD COLUMN scopes                  TEXT NOT NULL DEFAULT '[]';
ALTER TABLE oauth_clients ADD COLUMN token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none';
ALTER TABLE oauth_clients ADD COLUMN audience                TEXT NOT NULL DEFAULT '';
