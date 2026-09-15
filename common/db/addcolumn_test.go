package db

// addcolumn_test.go pins the scope of the one error the migration runner
// tolerates. "duplicate column name" means "this column is already here" from an
// ADD COLUMN, and means "this migration is wrong" from anything else — and since
// the ledger records a migration the moment it finishes, tolerating it too
// widely turns a typo into a permanent, silent wrong answer.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAddColumn(t *testing.T) {
	tests := []struct {
		stmt string
		want bool
	}{
		{"ALTER TABLE t ADD COLUMN label TEXT", true},
		{"alter table t add column label text", true},
		// SQLite makes the COLUMN keyword optional.
		{"ALTER TABLE t ADD label TEXT", true},
		{"ALTER TABLE main.t ADD COLUMN label TEXT", true},
		{`ALTER TABLE "my table" ADD COLUMN label TEXT`, true},
		{"ALTER TABLE [my table] ADD COLUMN label TEXT", true},
		{"ALTER\n\tTABLE t\n\tADD COLUMN label TEXT", true},
		// A column whose name merely starts with the keyword.
		{"ALTER TABLE t ADD COLUMN dropped_at TEXT", true},

		// The forms that produce the same error for a different reason.
		{"ALTER TABLE t RENAME COLUMN width TO depth", false},
		{"ALTER TABLE t RENAME TO u", false},
		{"ALTER TABLE t DROP COLUMN label", false},
		{"CREATE TABLE t (id TEXT, name TEXT, name TEXT)", false},
		{"CREATE INDEX ix ON t(label)", false},
		{"INSERT INTO t (label) VALUES ('ALTER TABLE t ADD COLUMN x')", false},

		// A table quoted because it collides with the keyword must not be read
		// as the clause itself.
		{`ALTER TABLE "add" RENAME COLUMN width TO depth`, false},
		{`ALTER TABLE "add" ADD COLUMN label TEXT`, true},

		// Not an ALTER TABLE at all.
		{"ALTER", false},
		{"ALTER TABLE t", false},
		{"", false},
		{"ALTERED TABLE t ADD COLUMN label TEXT", false},
	}

	for _, tc := range tests {
		t.Run(tc.stmt, func(t *testing.T) {
			assert.Equal(t, tc.want, isAddColumn(tc.stmt))
		})
	}
}
