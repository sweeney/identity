package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
)

// UserStore is the SQLite-backed implementation of domain.UserRepository.
type UserStore struct {
	db *db.Database
}

// NewUserStore creates a UserStore backed by the given Database.
func NewUserStore(database *db.Database) *UserStore {
	return &UserStore{db: database}
}

func (s *UserStore) Create(user *domain.User) error {
	_, err := s.db.DB().Exec(
		`INSERT INTO users (id, username, display_name, password_hash, role, is_active, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		user.ID,
		user.Username,
		user.DisplayName,
		user.PasswordHash,
		string(user.Role),
		boolToInt(user.IsActive),
		formatTime(user.CreatedAt),
		formatTime(user.UpdatedAt),
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return domain.ErrConflict
		}
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func (s *UserStore) GetByID(id string) (*domain.User, error) {
	row := s.db.DB().QueryRow(
		`SELECT id, username, display_name, password_hash, role, is_active, created_at, updated_at
		 FROM users WHERE id = ?`, id,
	)
	return scanUser(row)
}

func (s *UserStore) GetByUsername(username string) (*domain.User, error) {
	row := s.db.DB().QueryRow(
		`SELECT id, username, display_name, password_hash, role, is_active, created_at, updated_at
		 FROM users WHERE username = ? COLLATE NOCASE`, username,
	)
	return scanUser(row)
}

func (s *UserStore) Update(user *domain.User) error {
	res, err := s.db.DB().Exec(
		`UPDATE users SET username=?, display_name=?, password_hash=?, role=?, is_active=?, updated_at=?
		 WHERE id=?`,
		user.Username,
		user.DisplayName,
		user.PasswordHash,
		string(user.Role),
		boolToInt(user.IsActive),
		formatTime(time.Now().UTC()),
		user.ID,
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return domain.ErrConflict
		}
		return fmt.Errorf("update user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *UserStore) Delete(id string) error {
	res, err := s.db.DB().Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *UserStore) List() ([]*domain.User, error) {
	rows, err := s.db.DB().Query(
		`SELECT id, username, display_name, password_hash, role, is_active, created_at, updated_at
		 FROM users ORDER BY username`,
	)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		u, err := scanUserRow(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *UserStore) Count() (int, error) {
	var count int
	err := s.db.DB().QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

// scanUser scans a single *sql.Row into a User.
func scanUser(row *sql.Row) (*domain.User, error) {
	var u domain.User
	var role string
	var isActive int
	var createdAt, updatedAt string

	err := row.Scan(
		&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash,
		&role, &isActive, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}

	u.Role = domain.Role(role)
	u.IsActive = isActive == 1
	u.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	u.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return &u, nil
}

// scanUserRow scans a *sql.Rows (plural) row into a User.
func scanUserRow(rows *sql.Rows) (*domain.User, error) {
	var u domain.User
	var role string
	var isActive int
	var createdAt, updatedAt string

	err := rows.Scan(
		&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash,
		&role, &isActive, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan user row: %w", err)
	}

	u.Role = domain.Role(role)
	u.IsActive = isActive == 1
	u.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	u.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return &u, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func isUniqueConstraint(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
