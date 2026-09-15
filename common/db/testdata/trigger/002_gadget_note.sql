/* A trigger body is a compound statement: the semicolons inside BEGIN ... END
   terminate the statements within the block, not the CREATE TRIGGER itself. */
CREATE TRIGGER IF NOT EXISTS gadgets_touched
    AFTER UPDATE ON gadgets
    FOR EACH ROW
BEGIN
    UPDATE gadgets
       SET touched = CASE WHEN OLD.touched < 0 THEN 0 ELSE OLD.touched + 1 END
     WHERE id = OLD.id;
END;

ALTER TABLE gadgets ADD COLUMN note TEXT NOT NULL DEFAULT '';
