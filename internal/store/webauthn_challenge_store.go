package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
)

// WebAuthnChallengeStore is the SQLite-backed implementation of domain.WebAuthnChallengeRepository.
type WebAuthnChallengeStore struct {
	db *db.Database
}

// NewWebAuthnChallengeStore creates a WebAuthnChallengeStore backed by the given Database.
func NewWebAuthnChallengeStore(database *db.Database) *WebAuthnChallengeStore {
	return &WebAuthnChallengeStore{db: database}
}

func (s *WebAuthnChallengeStore) Create(ch *domain.WebAuthnChallenge) error {
	_, err := s.db.DB().Exec(
		`INSERT INTO webauthn_challenges (id, user_id, challenge, type, session_data, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ch.ID,
		ch.UserID,
		ch.Challenge,
		ch.Type,
		ch.SessionData,
		formatTime(ch.CreatedAt),
		formatTime(ch.ExpiresAt),
	)
	if err != nil {
		return fmt.Errorf("create webauthn challenge: %w", err)
	}
	return nil
}

func (s *WebAuthnChallengeStore) GetByID(id string) (*domain.WebAuthnChallenge, error) {
	var ch domain.WebAuthnChallenge
	var userID sql.NullString
	var createdAt, expiresAt string

	err := s.db.DB().QueryRow(
		`SELECT id, user_id, challenge, type, session_data, created_at, expires_at
		 FROM webauthn_challenges WHERE id = ?`, id,
	).Scan(&ch.ID, &userID, &ch.Challenge, &ch.Type, &ch.SessionData, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get webauthn challenge: %w", err)
	}

	if userID.Valid {
		ch.UserID = userID.String
	}
	ch.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	ch.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expiresAt)
	return &ch, nil
}

func (s *WebAuthnChallengeStore) Delete(id string) error {
	_, err := s.db.DB().Exec(`DELETE FROM webauthn_challenges WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete webauthn challenge: %w", err)
	}
	return nil
}

func (s *WebAuthnChallengeStore) DeleteExpired() error {
	_, err := s.db.DB().Exec(
		`DELETE FROM webauthn_challenges WHERE expires_at < ?`,
		formatTime(time.Now().UTC()),
	)
	if err != nil {
		return fmt.Errorf("delete expired webauthn challenges: %w", err)
	}
	return nil
}
