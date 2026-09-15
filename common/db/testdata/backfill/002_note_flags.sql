-- `pinned` is part of 001 on a database created today, and absent on one created
-- before 001 grew it. SQLite has no ADD COLUMN IF NOT EXISTS, so the only way to
-- reach the older databases is to add it unconditionally and let the runner skip
-- the ones that already have it.
ALTER TABLE notes ADD COLUMN pinned   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE notes ADD COLUMN archived INTEGER NOT NULL DEFAULT 0;
