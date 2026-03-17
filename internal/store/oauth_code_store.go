package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
)

// OAuthCodeStore is the SQLite-backed implementation of domain.OAuthCodeRepository.
type OAuthCodeStore struct {
	db *db.Database
}

// NewOAuthCodeStore creates an OAuthCodeStore backed by the given Database.
func NewOAuthCodeStore(database *db.Database) *OAuthCodeStore {
	return &OAuthCodeStore{db: database}
}

func (s *OAuthCodeStore) Create(code *domain.AuthCode) error {
	_, err := s.db.DB().Exec(
		`INSERT INTO oauth_auth_codes
		 (id, code_hash, client_id, user_id, redirect_uri, code_challenge, issued_at, expires_at, used_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		code.ID,
		code.CodeHash,
		code.ClientID,
		code.UserID,
		code.RedirectURI,
		code.CodeChallenge,
		formatTime(code.IssuedAt),
		formatTime(code.ExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("create auth code: %w", err)
	}
	return nil
}

func (s *OAuthCodeStore) GetByHash(codeHash string) (*domain.AuthCode, error) {
	row := s.db.DB().QueryRow(
		`SELECT id, code_hash, client_id, user_id, redirect_uri, code_challenge, issued_at, expires_at, used_at
		 FROM oauth_auth_codes WHERE code_hash = ?`, codeHash,
	)
	return scanAuthCode(row)
}

func (s *OAuthCodeStore) MarkUsed(id string, usedAt time.Time) error {
	res, err := s.db.DB().Exec(
		`UPDATE oauth_auth_codes SET used_at = ? WHERE id = ? AND used_at IS NULL`,
		formatTime(usedAt),
		id,
	)
	if err != nil {
		return fmt.Errorf("mark code used: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *OAuthCodeStore) DeleteExpiredAndUsed() error {
	_, err := s.db.DB().Exec(
		`DELETE FROM oauth_auth_codes
		 WHERE expires_at < ? OR used_at IS NOT NULL`,
		formatTime(time.Now().UTC()),
	)
	return err
}

func scanAuthCode(row *sql.Row) (*domain.AuthCode, error) {
	var c domain.AuthCode
	var issuedAt, expiresAt string
	var usedAt sql.NullString

	err := row.Scan(
		&c.ID, &c.CodeHash, &c.ClientID, &c.UserID,
		&c.RedirectURI, &c.CodeChallenge, &issuedAt, &expiresAt, &usedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan auth code: %w", err)
	}

	c.IssuedAt, _ = time.Parse(time.RFC3339Nano, issuedAt)
	c.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expiresAt)
	if usedAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, usedAt.String)
		c.UsedAt = &t
	}
	return &c, nil
}
