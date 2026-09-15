-- Widen widgets. The id stays authoritative; the label is new.
--
-- The semicolon in the sentence above is the whole point of this fixture: it is
-- ordinary prose punctuation, and nothing but a comment-blind splitter can be
-- hurt by it.
ALTER TABLE widgets ADD COLUMN label TEXT;
