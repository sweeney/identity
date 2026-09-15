package db

// split_test.go pins down the statement splitter that #44 tripped over. The
// old one was `strings.Split(body, ";")`, which is correct only for SQL that
// contains no comments, no string literals and no compound statements.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitStatements(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want []string
	}{
		{
			name: "plain statements",
			sql:  "CREATE TABLE t (id INTEGER);\nALTER TABLE t ADD COLUMN label TEXT;",
			want: []string{"CREATE TABLE t (id INTEGER)", "ALTER TABLE t ADD COLUMN label TEXT"},
		},
		{
			name: "trailing statement without a terminator",
			sql:  "ALTER TABLE t ADD COLUMN label TEXT",
			want: []string{"ALTER TABLE t ADD COLUMN label TEXT"},
		},
		{
			name: "line comment containing a semicolon",
			sql:  "-- The id stays authoritative; the label is new.\nALTER TABLE t ADD COLUMN label TEXT;",
			want: []string{"ALTER TABLE t ADD COLUMN label TEXT"},
		},
		{
			name: "trailing line comment on a statement",
			sql:  "SELECT 1 -- one; not two\nFROM t;",
			want: []string{"SELECT 1 \nFROM t"},
		},
		{
			name: "block comment containing a semicolon",
			sql:  "/* first; second */ ALTER TABLE t ADD COLUMN label TEXT;",
			want: []string{"ALTER TABLE t ADD COLUMN label TEXT"},
		},
		{
			name: "unterminated block comment swallows the rest",
			sql:  "SELECT 1;\n/* dangling",
			want: []string{"SELECT 1"},
		},
		{
			name: "semicolon inside a string literal",
			sql:  "INSERT INTO t (label) VALUES ('a;b');\nSELECT 1;",
			want: []string{"INSERT INTO t (label) VALUES ('a;b')", "SELECT 1"},
		},
		{
			name: "escaped quote inside a string literal",
			sql:  "INSERT INTO t (label) VALUES ('it''s; fine');",
			want: []string{"INSERT INTO t (label) VALUES ('it''s; fine')"},
		},
		{
			name: "comment markers inside a string literal are literal",
			sql:  "INSERT INTO t (label) VALUES ('-- not a comment; really');",
			want: []string{"INSERT INTO t (label) VALUES ('-- not a comment; really')"},
		},
		{
			name: "quoted and bracketed identifiers",
			sql:  `CREATE TABLE "odd;name" ([another;one] TEXT);`,
			want: []string{`CREATE TABLE "odd;name" ([another;one] TEXT)`},
		},
		{
			name: "trigger body is one statement",
			sql: "CREATE TRIGGER x AFTER UPDATE ON t FOR EACH ROW\n" +
				"BEGIN\n  UPDATE t SET n = n + 1 WHERE id = OLD.id;\nEND;\n" +
				"ALTER TABLE t ADD COLUMN label TEXT;",
			want: []string{
				"CREATE TRIGGER x AFTER UPDATE ON t FOR EACH ROW\n" +
					"BEGIN\n  UPDATE t SET n = n + 1 WHERE id = OLD.id;\nEND",
				"ALTER TABLE t ADD COLUMN label TEXT",
			},
		},
		{
			name: "CASE inside a trigger body nests correctly",
			sql: "CREATE TRIGGER x AFTER UPDATE ON t BEGIN " +
				"UPDATE t SET n = CASE WHEN n < 0 THEN 0 ELSE n + 1 END WHERE id = OLD.id; END;\n" +
				"SELECT 1;",
			want: []string{
				"CREATE TRIGGER x AFTER UPDATE ON t BEGIN " +
					"UPDATE t SET n = CASE WHEN n < 0 THEN 0 ELSE n + 1 END WHERE id = OLD.id; END",
				"SELECT 1",
			},
		},
		{
			name: "bare CASE expression does not open a block",
			sql:  "UPDATE t SET n = CASE WHEN n IS NULL THEN 0 ELSE n END;\nSELECT 1;",
			want: []string{"UPDATE t SET n = CASE WHEN n IS NULL THEN 0 ELSE n END", "SELECT 1"},
		},
		{
			name: "a leading BEGIN is transaction control, not a block",
			sql:  "BEGIN;\nSELECT 1;\nCOMMIT;",
			want: []string{"BEGIN", "SELECT 1", "COMMIT"},
		},
		{
			name: "comments only",
			sql:  "-- nothing to do here; really\n/* still nothing */\n",
			want: nil,
		},
		{
			name: "empty input",
			sql:  "",
			want: nil,
		},
		{
			name: "consecutive and trailing semicolons produce no empty statements",
			sql:  ";;SELECT 1;;\n;",
			want: []string{"SELECT 1"},
		},
		{
			name: "minus signs are not comments",
			sql:  "SELECT 1 - 2;",
			want: []string{"SELECT 1 - 2"},
		},
		{
			name: "identifiers are matched whole, not as substrings",
			sql:  "SELECT ended, beginning, casement FROM t;\nSELECT 2;",
			want: []string{"SELECT ended, beginning, casement FROM t", "SELECT 2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, splitStatements(tc.sql))
		})
	}
}
