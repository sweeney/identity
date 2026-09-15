-- A broken rename: `depth` is already a column. SQLite reports this as
-- "error in table boxes after rename: duplicate column name: depth" — the same
-- phrase an already-applied ADD COLUMN produces, from a statement that has
-- simply not been thought through.
ALTER TABLE boxes RENAME COLUMN width TO depth;
