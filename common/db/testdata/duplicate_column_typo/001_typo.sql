-- A copy-paste slip: `name` appears twice in the column list. SQLite reports it
-- as "duplicate column name", the same message an already-applied ADD COLUMN
-- produces — but it means a typo, not a column already in place.
CREATE TABLE IF NOT EXISTS typo (
    id   TEXT PRIMARY KEY,
    name TEXT,
    name TEXT
);
