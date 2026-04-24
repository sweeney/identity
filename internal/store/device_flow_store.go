package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
)

// --- DeviceAuthorizationStore ---

// DeviceAuthorizationStore is the SQLite-backed implementation of
// domain.DeviceAuthorizationRepository.
type DeviceAuthorizationStore struct {
	db *db.Database
}

// NewDeviceAuthorizationStore creates a DeviceAuthorizationStore backed by the given Database.
func NewDeviceAuthorizationStore(database *db.Database) *DeviceAuthorizationStore {
	return &DeviceAuthorizationStore{db: database}
}

func (s *DeviceAuthorizationStore) Create(da *domain.DeviceAuthorization) error {
	var claimCodeID sql.NullString
	if da.ClaimCodeID != "" {
		claimCodeID = sql.NullString{String: da.ClaimCodeID, Valid: true}
	}
	var userID sql.NullString
	if da.UserID != "" {
		userID = sql.NullString{String: da.UserID, Valid: true}
	}

	_, err := s.db.DB().Exec(
		`INSERT INTO oauth_device_codes
		 (id, device_code_hash, user_code, client_id, claim_code_id, scope, status,
		  user_id, issued_at, expires_at, last_polled_at, poll_interval, consumed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL)`,
		da.ID,
		da.DeviceCodeHash,
		da.UserCode,
		da.ClientID,
		claimCodeID,
		da.Scope,
		da.Status,
		userID,
		formatTime(da.IssuedAt),
		formatTime(da.ExpiresAt),
		da.PollInterval,
	)
	if err != nil {
		return fmt.Errorf("create device authorization: %w", err)
	}
	return nil
}

func (s *DeviceAuthorizationStore) GetByDeviceHash(hash string) (*domain.DeviceAuthorization, error) {
	row := s.db.DB().QueryRow(
		`SELECT id, device_code_hash, user_code, client_id, claim_code_id, scope, status,
		        user_id, issued_at, expires_at, last_polled_at, poll_interval, consumed_at
		 FROM oauth_device_codes WHERE device_code_hash = ?`, hash,
	)
	return scanDeviceAuthorization(row)
}

func (s *DeviceAuthorizationStore) GetByUserCode(userCode string) (*domain.DeviceAuthorization, error) {
	row := s.db.DB().QueryRow(
		`SELECT id, device_code_hash, user_code, client_id, claim_code_id, scope, status,
		        user_id, issued_at, expires_at, last_polled_at, poll_interval, consumed_at
		 FROM oauth_device_codes WHERE user_code = ?`, userCode,
	)
	return scanDeviceAuthorization(row)
}

func (s *DeviceAuthorizationStore) ListPendingByClaimID(claimCodeID string) ([]*domain.DeviceAuthorization, error) {
	rows, err := s.db.DB().Query(
		`SELECT id, device_code_hash, user_code, client_id, claim_code_id, scope, status,
		        user_id, issued_at, expires_at, last_polled_at, poll_interval, consumed_at
		 FROM oauth_device_codes
		 WHERE claim_code_id = ? AND status = ? AND expires_at >= ?`,
		claimCodeID, domain.DeviceStatusPending, formatTime(time.Now().UTC()),
	)
	if err != nil {
		return nil, fmt.Errorf("list pending by claim id: %w", err)
	}
	defer rows.Close()

	var out []*domain.DeviceAuthorization
	for rows.Next() {
		da, err := scanDeviceAuthorizationRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, da)
	}
	return out, rows.Err()
}

func (s *DeviceAuthorizationStore) Approve(id, userID string, approvedAt time.Time) error {
	res, err := s.db.DB().Exec(
		`UPDATE oauth_device_codes
		 SET status = ?, user_id = ?
		 WHERE id = ? AND status = ?`,
		domain.DeviceStatusApproved, userID, id, domain.DeviceStatusPending,
	)
	_ = approvedAt // status transition timestamp is implicit from the status column
	if err != nil {
		return fmt.Errorf("approve device authorization: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *DeviceAuthorizationStore) Deny(id string, deniedAt time.Time) error {
	res, err := s.db.DB().Exec(
		`UPDATE oauth_device_codes
		 SET status = ?
		 WHERE id = ? AND status = ?`,
		domain.DeviceStatusDenied, id, domain.DeviceStatusPending,
	)
	_ = deniedAt
	if err != nil {
		return fmt.Errorf("deny device authorization: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *DeviceAuthorizationStore) MarkPolled(id string, polledAt time.Time) error {
	res, err := s.db.DB().Exec(
		`UPDATE oauth_device_codes SET last_polled_at = ? WHERE id = ?`,
		formatTime(polledAt), id,
	)
	if err != nil {
		return fmt.Errorf("mark device authorization polled: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *DeviceAuthorizationStore) MarkConsumed(id string, consumedAt time.Time) error {
	// Atomic single-consume: only set consumed_at when it's currently NULL. A second
	// call returns ErrNotFound, preventing an approved device_code from being
	// exchanged for tokens more than once.
	res, err := s.db.DB().Exec(
		`UPDATE oauth_device_codes
		 SET consumed_at = ?
		 WHERE id = ? AND consumed_at IS NULL`,
		formatTime(consumedAt), id,
	)
	if err != nil {
		return fmt.Errorf("mark device authorization consumed: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *DeviceAuthorizationStore) DeleteExpired() error {
	_, err := s.db.DB().Exec(
		`DELETE FROM oauth_device_codes WHERE expires_at < ?`,
		formatTime(time.Now().UTC()),
	)
	if err != nil {
		return fmt.Errorf("delete expired device authorizations: %w", err)
	}
	return nil
}

type daScanner interface {
	Scan(dest ...any) error
}

func scanDeviceAuthorization(row *sql.Row) (*domain.DeviceAuthorization, error) {
	da, err := scanDeviceAuthorizationFrom(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan device authorization: %w", err)
	}
	return da, nil
}

func scanDeviceAuthorizationRows(rows *sql.Rows) (*domain.DeviceAuthorization, error) {
	da, err := scanDeviceAuthorizationFrom(rows)
	if err != nil {
		return nil, fmt.Errorf("scan device authorization: %w", err)
	}
	return da, nil
}

// scanDeviceAuthorizationFrom returns the raw Scan error (including sql.ErrNoRows)
// so callers can distinguish not-found from other errors.
func scanDeviceAuthorizationFrom(sc daScanner) (*domain.DeviceAuthorization, error) {
	var da domain.DeviceAuthorization
	var claimCodeID, userID sql.NullString
	var issuedAt, expiresAt string
	var lastPolledAt, consumedAt sql.NullString

	if err := sc.Scan(
		&da.ID,
		&da.DeviceCodeHash,
		&da.UserCode,
		&da.ClientID,
		&claimCodeID,
		&da.Scope,
		&da.Status,
		&userID,
		&issuedAt,
		&expiresAt,
		&lastPolledAt,
		&da.PollInterval,
		&consumedAt,
	); err != nil {
		return nil, err
	}

	if claimCodeID.Valid {
		da.ClaimCodeID = claimCodeID.String
	}
	if userID.Valid {
		da.UserID = userID.String
	}
	da.IssuedAt, _ = time.Parse(time.RFC3339Nano, issuedAt)
	da.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expiresAt)
	if lastPolledAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, lastPolledAt.String)
		da.LastPolledAt = &t
	}
	if consumedAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, consumedAt.String)
		da.ConsumedAt = &t
	}
	return &da, nil
}

// --- ClaimCodeStore ---

// ClaimCodeStore is the SQLite-backed implementation of domain.ClaimCodeRepository.
type ClaimCodeStore struct {
	db *db.Database
}

// NewClaimCodeStore creates a ClaimCodeStore backed by the given Database.
func NewClaimCodeStore(database *db.Database) *ClaimCodeStore {
	return &ClaimCodeStore{db: database}
}

func (s *ClaimCodeStore) Create(c *domain.ClaimCode) error {
	var boundUser sql.NullString
	if c.BoundUserID != "" {
		boundUser = sql.NullString{String: c.BoundUserID, Valid: true}
	}
	var boundAt, revokedAt sql.NullString
	if c.BoundAt != nil {
		boundAt = sql.NullString{String: formatTime(*c.BoundAt), Valid: true}
	}
	if c.RevokedAt != nil {
		revokedAt = sql.NullString{String: formatTime(*c.RevokedAt), Valid: true}
	}

	_, err := s.db.DB().Exec(
		`INSERT INTO oauth_claim_codes
		 (id, code_hash, client_id, label, bound_user_id, created_at, bound_at, revoked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.CodeHash, c.ClientID, c.Label, boundUser,
		formatTime(c.CreatedAt), boundAt, revokedAt,
	)
	if err != nil {
		return fmt.Errorf("create claim code: %w", err)
	}
	return nil
}

func (s *ClaimCodeStore) GetByID(id string) (*domain.ClaimCode, error) {
	row := s.db.DB().QueryRow(
		`SELECT id, code_hash, client_id, label, bound_user_id, created_at, bound_at, revoked_at
		 FROM oauth_claim_codes WHERE id = ?`, id,
	)
	return scanClaimCode(row)
}

func (s *ClaimCodeStore) GetByHash(hash string) (*domain.ClaimCode, error) {
	row := s.db.DB().QueryRow(
		`SELECT id, code_hash, client_id, label, bound_user_id, created_at, bound_at, revoked_at
		 FROM oauth_claim_codes WHERE code_hash = ?`, hash,
	)
	return scanClaimCode(row)
}

func (s *ClaimCodeStore) ListByClient(clientID string) ([]*domain.ClaimCode, error) {
	rows, err := s.db.DB().Query(
		`SELECT id, code_hash, client_id, label, bound_user_id, created_at, bound_at, revoked_at
		 FROM oauth_claim_codes WHERE client_id = ? ORDER BY created_at DESC`, clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("list claim codes: %w", err)
	}
	defer rows.Close()

	var out []*domain.ClaimCode
	for rows.Next() {
		c, err := scanClaimCodeRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *ClaimCodeStore) Bind(id, userID string, boundAt time.Time) error {
	res, err := s.db.DB().Exec(
		`UPDATE oauth_claim_codes
		 SET bound_user_id = ?, bound_at = ?
		 WHERE id = ? AND revoked_at IS NULL`,
		userID, formatTime(boundAt), id,
	)
	if err != nil {
		return fmt.Errorf("bind claim code: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *ClaimCodeStore) Revoke(id string, revokedAt time.Time) error {
	res, err := s.db.DB().Exec(
		`UPDATE oauth_claim_codes SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		formatTime(revokedAt), id,
	)
	if err != nil {
		return fmt.Errorf("revoke claim code: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func scanClaimCode(row *sql.Row) (*domain.ClaimCode, error) {
	var c domain.ClaimCode
	var boundUser sql.NullString
	var createdAt string
	var boundAt, revokedAt sql.NullString

	err := row.Scan(&c.ID, &c.CodeHash, &c.ClientID, &c.Label, &boundUser, &createdAt, &boundAt, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan claim code: %w", err)
	}

	if boundUser.Valid {
		c.BoundUserID = boundUser.String
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	if boundAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, boundAt.String)
		c.BoundAt = &t
	}
	if revokedAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, revokedAt.String)
		c.RevokedAt = &t
	}
	return &c, nil
}

func scanClaimCodeRow(rows *sql.Rows) (*domain.ClaimCode, error) {
	var c domain.ClaimCode
	var boundUser sql.NullString
	var createdAt string
	var boundAt, revokedAt sql.NullString

	if err := rows.Scan(&c.ID, &c.CodeHash, &c.ClientID, &c.Label, &boundUser, &createdAt, &boundAt, &revokedAt); err != nil {
		return nil, fmt.Errorf("scan claim code: %w", err)
	}
	if boundUser.Valid {
		c.BoundUserID = boundUser.String
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	if boundAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, boundAt.String)
		c.BoundAt = &t
	}
	if revokedAt.Valid {
		t, _ := time.Parse(time.RFC3339Nano, revokedAt.String)
		c.RevokedAt = &t
	}
	return &c, nil
}
