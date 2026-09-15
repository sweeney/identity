-- SQLite makes the COLUMN keyword optional, and a schema-qualified table name
-- is legal too. Both still have to be recognised as ADD COLUMN, or the backfill
-- pattern stops working for anyone who writes it this way.
ALTER TABLE main.crates ADD label TEXT NOT NULL DEFAULT '';
ALTER TABLE crates ADD weight INTEGER NOT NULL DEFAULT 0;
