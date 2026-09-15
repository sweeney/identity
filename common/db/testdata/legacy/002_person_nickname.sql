-- Nicknames are optional; the real name stays required.
ALTER TABLE people ADD COLUMN nickname TEXT NOT NULL DEFAULT '';
