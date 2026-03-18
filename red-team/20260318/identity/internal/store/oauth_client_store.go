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

// OAuthClientStore is the SQLite-backed implementation of domain.OAuthClientRepository.
type OAuthClientStore struct {
	db *db.Database
}

// NewOAuthClientStore creates an OAuthClientStore backed by the given Database.
func NewOAuthClientStore(database *db.Database) *OAuthClientStore {
	return &OAuthClientStore{db: database}
}

func (s *OAuthClientStore) Create(client *domain.OAuthClient) error {
	uris, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return fmt.Errorf("marshal redirect_uris: %w", err)
	}
	_, err = s.db.DB().Exec(
		`INSERT INTO oauth_clients (id, name, redirect_uris, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		client.ID,
		client.Name,
		string(uris),
		formatTime(client.CreatedAt),
		formatTime(client.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("create oauth client: %w", err)
	}
	return nil
}

func (s *OAuthClientStore) GetByID(id string) (*domain.OAuthClient, error) {
	row := s.db.DB().QueryRow(
		`SELECT id, name, redirect_uris, created_at, updated_at
		 FROM oauth_clients WHERE id = ?`, id,
	)
	return scanOAuthClient(row)
}

func (s *OAuthClientStore) List() ([]*domain.OAuthClient, error) {
	rows, err := s.db.DB().Query(
		`SELECT id, name, redirect_uris, created_at, updated_at
		 FROM oauth_clients ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("list oauth clients: %w", err)
	}
	defer rows.Close()

	var clients []*domain.OAuthClient
	for rows.Next() {
		c, err := scanOAuthClientRow(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func (s *OAuthClientStore) Update(client *domain.OAuthClient) error {
	uris, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return fmt.Errorf("marshal redirect_uris: %w", err)
	}
	res, err := s.db.DB().Exec(
		`UPDATE oauth_clients SET name=?, redirect_uris=?, updated_at=? WHERE id=?`,
		client.Name,
		string(uris),
		formatTime(time.Now().UTC()),
		client.ID,
	)
	if err != nil {
		return fmt.Errorf("update oauth client: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *OAuthClientStore) Delete(id string) error {
	res, err := s.db.DB().Exec(`DELETE FROM oauth_clients WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete oauth client: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func scanOAuthClient(row *sql.Row) (*domain.OAuthClient, error) {
	var c domain.OAuthClient
	var urisJSON, createdAt, updatedAt string

	err := row.Scan(&c.ID, &c.Name, &urisJSON, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan oauth client: %w", err)
	}

	if err := json.Unmarshal([]byte(urisJSON), &c.RedirectURIs); err != nil {
		return nil, fmt.Errorf("unmarshal redirect_uris: %w", err)
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	c.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return &c, nil
}

func scanOAuthClientRow(rows *sql.Rows) (*domain.OAuthClient, error) {
	var c domain.OAuthClient
	var urisJSON, createdAt, updatedAt string

	err := rows.Scan(&c.ID, &c.Name, &urisJSON, &createdAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("scan oauth client row: %w", err)
	}

	if err := json.Unmarshal([]byte(urisJSON), &c.RedirectURIs); err != nil {
		return nil, fmt.Errorf("unmarshal redirect_uris: %w", err)
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	c.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return &c, nil
}
