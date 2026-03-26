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
	grantTypes, err := json.Marshal(client.GrantTypes)
	if err != nil {
		return fmt.Errorf("marshal grant_types: %w", err)
	}
	scopes, err := json.Marshal(client.Scopes)
	if err != nil {
		return fmt.Errorf("marshal scopes: %w", err)
	}
	_, err = s.db.DB().Exec(
		`INSERT INTO oauth_clients (id, name, redirect_uris, client_secret_hash, client_secret_hash_prev, grant_types, scopes, token_endpoint_auth_method, audience, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		client.ID,
		client.Name,
		string(uris),
		client.SecretHash,
		client.SecretHashPrev,
		string(grantTypes),
		string(scopes),
		client.TokenEndpointAuthMethod,
		client.Audience,
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
		`SELECT id, name, redirect_uris, client_secret_hash, client_secret_hash_prev, grant_types, scopes, token_endpoint_auth_method, audience, created_at, updated_at
		 FROM oauth_clients WHERE id = ?`, id,
	)
	return scanOAuthClient(row)
}

func (s *OAuthClientStore) List() ([]*domain.OAuthClient, error) {
	rows, err := s.db.DB().Query(
		`SELECT id, name, redirect_uris, client_secret_hash, client_secret_hash_prev, grant_types, scopes, token_endpoint_auth_method, audience, created_at, updated_at
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
	grantTypes, err := json.Marshal(client.GrantTypes)
	if err != nil {
		return fmt.Errorf("marshal grant_types: %w", err)
	}
	scopes, err := json.Marshal(client.Scopes)
	if err != nil {
		return fmt.Errorf("marshal scopes: %w", err)
	}
	res, err := s.db.DB().Exec(
		`UPDATE oauth_clients SET name=?, redirect_uris=?, client_secret_hash=?, client_secret_hash_prev=?, grant_types=?, scopes=?, token_endpoint_auth_method=?, audience=?, updated_at=? WHERE id=?`,
		client.Name,
		string(uris),
		client.SecretHash,
		client.SecretHashPrev,
		string(grantTypes),
		string(scopes),
		client.TokenEndpointAuthMethod,
		client.Audience,
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
	var urisJSON, grantTypesJSON, scopesJSON, createdAt, updatedAt string

	err := row.Scan(&c.ID, &c.Name, &urisJSON, &c.SecretHash, &c.SecretHashPrev, &grantTypesJSON, &scopesJSON, &c.TokenEndpointAuthMethod, &c.Audience, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan oauth client: %w", err)
	}

	if err := json.Unmarshal([]byte(urisJSON), &c.RedirectURIs); err != nil {
		return nil, fmt.Errorf("unmarshal redirect_uris: %w", err)
	}
	if err := json.Unmarshal([]byte(grantTypesJSON), &c.GrantTypes); err != nil {
		return nil, fmt.Errorf("unmarshal grant_types: %w", err)
	}
	if err := json.Unmarshal([]byte(scopesJSON), &c.Scopes); err != nil {
		return nil, fmt.Errorf("unmarshal scopes: %w", err)
	}
	// Normalize nil slices to empty (JSON "null" → nil, but callers expect [])
	if c.RedirectURIs == nil {
		c.RedirectURIs = []string{}
	}
	if c.GrantTypes == nil {
		c.GrantTypes = []string{}
	}
	if c.Scopes == nil {
		c.Scopes = []string{}
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	c.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return &c, nil
}

func scanOAuthClientRow(rows *sql.Rows) (*domain.OAuthClient, error) {
	var c domain.OAuthClient
	var urisJSON, grantTypesJSON, scopesJSON, createdAt, updatedAt string

	err := rows.Scan(&c.ID, &c.Name, &urisJSON, &c.SecretHash, &c.SecretHashPrev, &grantTypesJSON, &scopesJSON, &c.TokenEndpointAuthMethod, &c.Audience, &createdAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("scan oauth client row: %w", err)
	}

	if err := json.Unmarshal([]byte(urisJSON), &c.RedirectURIs); err != nil {
		return nil, fmt.Errorf("unmarshal redirect_uris: %w", err)
	}
	if err := json.Unmarshal([]byte(grantTypesJSON), &c.GrantTypes); err != nil {
		return nil, fmt.Errorf("unmarshal grant_types: %w", err)
	}
	if err := json.Unmarshal([]byte(scopesJSON), &c.Scopes); err != nil {
		return nil, fmt.Errorf("unmarshal scopes: %w", err)
	}
	if c.RedirectURIs == nil {
		c.RedirectURIs = []string{}
	}
	if c.GrantTypes == nil {
		c.GrantTypes = []string{}
	}
	if c.Scopes == nil {
		c.Scopes = []string{}
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	c.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	return &c, nil
}
