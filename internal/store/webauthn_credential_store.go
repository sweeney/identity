package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
)

// WebAuthnCredentialStore is the SQLite-backed implementation of domain.WebAuthnCredentialRepository.
type WebAuthnCredentialStore struct {
	db *db.Database
}

// NewWebAuthnCredentialStore creates a WebAuthnCredentialStore backed by the given Database.
func NewWebAuthnCredentialStore(database *db.Database) *WebAuthnCredentialStore {
	return &WebAuthnCredentialStore{db: database}
}

func (s *WebAuthnCredentialStore) Create(cred *domain.WebAuthnCredential) error {
	transports, err := json.Marshal(cred.Transports)
	if err != nil {
		return fmt.Errorf("marshal transports: %w", err)
	}

	_, err = s.db.DB().Exec(
		`INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, attestation_type, aaguid, sign_count, transports, backup_eligible, backup_state, name, created_at, last_used_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cred.ID,
		cred.UserID,
		cred.CredentialID,
		cred.PublicKey,
		cred.AttestationType,
		cred.AAGUID,
		cred.SignCount,
		string(transports),
		boolToInt(cred.BackupEligible),
		boolToInt(cred.BackupState),
		cred.Name,
		formatTime(cred.CreatedAt),
		formatTime(cred.LastUsedAt),
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return domain.ErrConflict
		}
		return fmt.Errorf("create webauthn credential: %w", err)
	}
	return nil
}

func (s *WebAuthnCredentialStore) GetByCredentialID(credentialID []byte) (*domain.WebAuthnCredential, error) {
	row := s.db.DB().QueryRow(
		`SELECT id, user_id, credential_id, public_key, attestation_type, aaguid, sign_count, transports, backup_eligible, backup_state, name, created_at, last_used_at
		 FROM webauthn_credentials WHERE credential_id = ?`, credentialID,
	)
	return scanWebAuthnCredential(row)
}

func (s *WebAuthnCredentialStore) ListByUserID(userID string) ([]*domain.WebAuthnCredential, error) {
	rows, err := s.db.DB().Query(
		`SELECT id, user_id, credential_id, public_key, attestation_type, aaguid, sign_count, transports, backup_eligible, backup_state, name, created_at, last_used_at
		 FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list webauthn credentials: %w", err)
	}
	defer rows.Close()

	var creds []*domain.WebAuthnCredential
	for rows.Next() {
		c, err := scanWebAuthnCredentialRow(rows)
		if err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

func (s *WebAuthnCredentialStore) UpdateSignCount(id string, signCount uint32) error {
	res, err := s.db.DB().Exec(
		`UPDATE webauthn_credentials SET sign_count = ? WHERE id = ?`,
		signCount, id,
	)
	if err != nil {
		return fmt.Errorf("update sign count: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *WebAuthnCredentialStore) UpdateLastUsed(id string, t time.Time) error {
	res, err := s.db.DB().Exec(
		`UPDATE webauthn_credentials SET last_used_at = ? WHERE id = ?`,
		formatTime(t), id,
	)
	if err != nil {
		return fmt.Errorf("update last used: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *WebAuthnCredentialStore) Rename(id, name string) error {
	res, err := s.db.DB().Exec(
		`UPDATE webauthn_credentials SET name = ? WHERE id = ?`,
		name, id,
	)
	if err != nil {
		return fmt.Errorf("rename webauthn credential: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *WebAuthnCredentialStore) Delete(id string) error {
	res, err := s.db.DB().Exec(`DELETE FROM webauthn_credentials WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete webauthn credential: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *WebAuthnCredentialStore) DeleteAllForUser(userID string) error {
	_, err := s.db.DB().Exec(`DELETE FROM webauthn_credentials WHERE user_id = ?`, userID)
	if err != nil {
		return fmt.Errorf("delete all webauthn credentials: %w", err)
	}
	return nil
}

func scanWebAuthnCredential(row *sql.Row) (*domain.WebAuthnCredential, error) {
	var c domain.WebAuthnCredential
	var transports, createdAt, lastUsedAt string
	var aaguid []byte
	var backupEligible, backupState int

	err := row.Scan(
		&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey,
		&c.AttestationType, &aaguid, &c.SignCount,
		&transports, &backupEligible, &backupState,
		&c.Name, &createdAt, &lastUsedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan webauthn credential: %w", err)
	}

	c.AAGUID = aaguid
	c.BackupEligible = backupEligible == 1
	c.BackupState = backupState == 1
	if transports != "" {
		json.Unmarshal([]byte(transports), &c.Transports) //nolint:errcheck
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	c.LastUsedAt, _ = time.Parse(time.RFC3339Nano, lastUsedAt)
	return &c, nil
}

func scanWebAuthnCredentialRow(rows *sql.Rows) (*domain.WebAuthnCredential, error) {
	var c domain.WebAuthnCredential
	var transports, createdAt, lastUsedAt string
	var aaguid []byte
	var backupEligible, backupState int

	err := rows.Scan(
		&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey,
		&c.AttestationType, &aaguid, &c.SignCount,
		&transports, &backupEligible, &backupState,
		&c.Name, &createdAt, &lastUsedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan webauthn credential row: %w", err)
	}

	c.AAGUID = aaguid
	c.BackupEligible = backupEligible == 1
	c.BackupState = backupState == 1
	if transports != "" {
		json.Unmarshal([]byte(transports), &c.Transports) //nolint:errcheck
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	c.LastUsedAt, _ = time.Parse(time.RFC3339Nano, lastUsedAt)
	return &c, nil
}
