package db

import (
	"embed"

	commondb "github.com/sweeney/identity/common/db"
)

//go:embed migrations/*.sql
var identityMigrations embed.FS

//go:embed config_migrations/*.sql
var configMigrations embed.FS

// Database is an alias for the common Database type. All existing callers
// continue to use *db.Database without import changes.
type Database = commondb.Database

// Open opens (or creates) the identity SQLite database at path and runs
// all pending identity migrations.
func Open(path string) (*Database, error) {
	return commondb.OpenWithMigrations(path, identityMigrations, "migrations")
}

// OpenConfig opens (or creates) the config SQLite database at path and
// runs the embedded config migrations.
func OpenConfig(path string) (*Database, error) {
	return commondb.OpenWithMigrations(path, configMigrations, "config_migrations")
}
