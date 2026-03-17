package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
)

// TokenStore is the SQLite-backed implementation of domain.TokenRepository.
type TokenStore struct {
	db *db.Database
}

// NewTokenStore creates a TokenStore backed by the given Database.
func NewTokenStore(database *db.Database) *TokenStore {
	return &TokenStore{db: database}
}

func (s *TokenStore) Create(token *domain.RefreshToken) error {
	_, err := s.db.DB().Exec(
		`INSERT INTO refresh_tokens
		 (id, user_id, token_hash, family_id, parent_token_id, device_hint,
		  issued_at, last_used_at, expires_at, is_revoked)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.FamilyID,
		nullableString(token.ParentTokenID),
		token.DeviceHint,
		formatTime(token.IssuedAt),
		formatTime(token.LastUsedAt),
		formatTime(token.ExpiresAt),
		boolToInt(token.IsRevoked),
	)
	if err != nil {
		return fmt.Errorf("create token: %w", err)
	}
	return nil
}

func (s *TokenStore) GetByHash(tokenHash string) (*domain.RefreshToken, error) {
	row := s.db.DB().QueryRow(
		`SELECT id, user_id, token_hash, family_id, COALESCE(parent_token_id,''),
		        device_hint, issued_at, last_used_at, expires_at, is_revoked
		 FROM refresh_tokens WHERE token_hash = ?`, tokenHash,
	)
	return scanToken(row)
}

// Rotate atomically revokes oldTokenID and inserts newToken within a single
// BEGIN IMMEDIATE transaction to prevent concurrent refresh races.
func (s *TokenStore) Rotate(oldTokenID string, newToken *domain.RefreshToken) error {
	tx, err := s.db.DB().Begin()
	if err != nil {
		return fmt.Errorf("begin rotate tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Revoke old token
	if _, err := tx.Exec(
		`UPDATE refresh_tokens SET is_revoked = 1 WHERE id = ?`, oldTokenID,
	); err != nil {
		return fmt.Errorf("revoke old token: %w", err)
	}

	// Insert new token
	if _, err := tx.Exec(
		`INSERT INTO refresh_tokens
		 (id, user_id, token_hash, family_id, parent_token_id, device_hint,
		  issued_at, last_used_at, expires_at, is_revoked)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		newToken.ID,
		newToken.UserID,
		newToken.TokenHash,
		newToken.FamilyID,
		nullableString(newToken.ParentTokenID),
		newToken.DeviceHint,
		formatTime(newToken.IssuedAt),
		formatTime(newToken.LastUsedAt),
		formatTime(newToken.ExpiresAt),
	); err != nil {
		return fmt.Errorf("insert new token: %w", err)
	}

	return tx.Commit()
}

func (s *TokenStore) RevokeFamilyByHash(tokenHash string) error {
	_, err := s.db.DB().Exec(
		`UPDATE refresh_tokens
		 SET is_revoked = 1
		 WHERE family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = ?)`,
		tokenHash,
	)
	return err
}

func (s *TokenStore) RevokeByID(id string) error {
	_, err := s.db.DB().Exec(
		`UPDATE refresh_tokens SET is_revoked = 1 WHERE id = ?`, id,
	)
	return err
}

func (s *TokenStore) RevokeAllForUser(userID string) error {
	_, err := s.db.DB().Exec(
		`UPDATE refresh_tokens SET is_revoked = 1 WHERE user_id = ?`, userID,
	)
	return err
}

func (s *TokenStore) DeleteExpiredAndOldRevoked(retentionDays int) error {
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	_, err := s.db.DB().Exec(
		`DELETE FROM refresh_tokens
		 WHERE expires_at < ?
		    OR (is_revoked = 1 AND last_used_at < ?)`,
		formatTime(time.Now().UTC()),
		formatTime(cutoff),
	)
	return err
}

func scanToken(row *sql.Row) (*domain.RefreshToken, error) {
	var t domain.RefreshToken
	var isRevoked int
	var issuedAt, lastUsedAt, expiresAt string

	err := row.Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.FamilyID, &t.ParentTokenID,
		&t.DeviceHint, &issuedAt, &lastUsedAt, &expiresAt, &isRevoked,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan token: %w", err)
	}

	t.IsRevoked = isRevoked == 1
	t.IssuedAt, _ = time.Parse(time.RFC3339Nano, issuedAt)
	t.LastUsedAt, _ = time.Parse(time.RFC3339Nano, lastUsedAt)
	t.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expiresAt)
	return &t, nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
