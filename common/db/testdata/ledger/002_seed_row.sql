-- A one-shot data migration. It cannot be written idempotently without extra
-- ceremony, so a runner that re-executes every file on every boot duplicates it.
INSERT INTO seeds (note) VALUES ('one-shot');
