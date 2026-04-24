package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
)

// ConfigStore is the SQLite-backed implementation of domain.ConfigRepository.
type ConfigStore struct {
	db *db.Database
}

// NewConfigStore creates a ConfigStore backed by the given Database.
func NewConfigStore(database *db.Database) *ConfigStore {
	return &ConfigStore{db: database}
}

func (s *ConfigStore) List() ([]domain.ConfigNamespaceSummary, error) {
	rows, err := s.db.DB().Query(
		`SELECT name, read_role, write_role, updated_at, created_at
		 FROM config_namespaces ORDER BY name ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("list config namespaces: %w", err)
	}
	defer rows.Close()

	var out []domain.ConfigNamespaceSummary
	for rows.Next() {
		var (
			sum                  domain.ConfigNamespaceSummary
			updatedAt, createdAt string
		)
		if err := rows.Scan(&sum.Name, &sum.ReadRole, &sum.WriteRole, &updatedAt, &createdAt); err != nil {
			return nil, fmt.Errorf("scan config namespace: %w", err)
		}
		sum.UpdatedAt = parseTime(updatedAt)
		sum.CreatedAt = parseTime(createdAt)
		out = append(out, sum)
	}
	return out, rows.Err()
}

func (s *ConfigStore) Get(name string) (*domain.ConfigNamespace, error) {
	row := s.db.DB().QueryRow(
		`SELECT name, read_role, write_role, document, updated_at, updated_by, created_at
		 FROM config_namespaces WHERE name = ?`,
		name,
	)
	var (
		ns                   domain.ConfigNamespace
		document             string
		updatedAt, createdAt string
	)
	err := row.Scan(&ns.Name, &ns.ReadRole, &ns.WriteRole, &document, &updatedAt, &ns.UpdatedBy, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("get config namespace: %w", err)
	}
	ns.Document = []byte(document)
	ns.UpdatedAt = parseTime(updatedAt)
	ns.CreatedAt = parseTime(createdAt)
	return &ns, nil
}

func (s *ConfigStore) Create(ns *domain.ConfigNamespace) error {
	_, err := s.db.DB().Exec(
		`INSERT INTO config_namespaces
		   (name, read_role, write_role, document, updated_at, updated_by, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ns.Name,
		ns.ReadRole,
		ns.WriteRole,
		string(ns.Document),
		formatTime(ns.UpdatedAt),
		ns.UpdatedBy,
		formatTime(ns.CreatedAt),
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return domain.ErrConflict
		}
		return fmt.Errorf("create config namespace: %w", err)
	}
	return nil
}

func (s *ConfigStore) UpdateDocument(name string, document []byte, updatedBy string, at time.Time) error {
	res, err := s.db.DB().Exec(
		`UPDATE config_namespaces
		 SET document = ?, updated_at = ?, updated_by = ?
		 WHERE name = ?`,
		string(document),
		formatTime(at),
		updatedBy,
		name,
	)
	if err != nil {
		return fmt.Errorf("update config document: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *ConfigStore) UpdateACL(name, readRole, writeRole string, at time.Time) error {
	res, err := s.db.DB().Exec(
		`UPDATE config_namespaces
		 SET read_role = ?, write_role = ?, updated_at = ?
		 WHERE name = ?`,
		readRole,
		writeRole,
		formatTime(at),
		name,
	)
	if err != nil {
		return fmt.Errorf("update config acl: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *ConfigStore) Delete(name string) error {
	res, err := s.db.DB().Exec(`DELETE FROM config_namespaces WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("delete config namespace: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// parseTime parses an RFC3339Nano timestamp stored by formatTime. Returns
// the zero value if parsing fails — callers should treat this as a
// corrupted row (should never happen in practice).
func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}
