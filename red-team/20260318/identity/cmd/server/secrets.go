package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"log"

	"github.com/sweeney/identity/internal/db"
)

const (
	metaJWTSecret     = "jwt_secret"
	metaJWTSecretPrev = "jwt_secret_prev"
)

// jwtSecrets holds the current and previous JWT signing secrets.
type jwtSecrets struct {
	Current  string
	Previous string
}

// resolveJWTSecrets determines the JWT secrets to use on startup.
//
// Priority:
//  1. JWT_SECRET env var (if set, overrides DB — backward compat)
//  2. jwt_secret in the metadata table
//  3. Generate a new random secret and store it in the DB
func resolveJWTSecrets(database *db.Database, envSecret, envPrevSecret string) (*jwtSecrets, error) {
	if envSecret != "" {
		// Env var takes precedence (backward compat / explicit override)
		return &jwtSecrets{Current: envSecret, Previous: envPrevSecret}, nil
	}

	// Try loading from DB
	current, err := getMetadata(database, metaJWTSecret)
	if err != nil {
		return nil, fmt.Errorf("read jwt secret from db: %w", err)
	}

	if current != "" {
		prev, _ := getMetadata(database, metaJWTSecretPrev)
		return &jwtSecrets{Current: current, Previous: prev}, nil
	}

	// First run — generate and store
	secret, err := generateSecret(64)
	if err != nil {
		return nil, fmt.Errorf("generate jwt secret: %w", err)
	}

	if err := setMetadata(database, metaJWTSecret, secret); err != nil {
		return nil, fmt.Errorf("store jwt secret: %w", err)
	}

	log.Println("Generated JWT signing secret (stored in database)")
	return &jwtSecrets{Current: secret}, nil
}

// rotateJWTSecret generates a new JWT secret, moves the current one to previous.
func rotateJWTSecret(database *db.Database) error {
	current, err := getMetadata(database, metaJWTSecret)
	if err != nil {
		return fmt.Errorf("read current secret: %w", err)
	}
	if current == "" {
		return fmt.Errorf("no existing JWT secret found — run the server first")
	}

	newSecret, err := generateSecret(64)
	if err != nil {
		return fmt.Errorf("generate new secret: %w", err)
	}

	// Move current → previous, set new → current
	if err := setMetadata(database, metaJWTSecretPrev, current); err != nil {
		return fmt.Errorf("store previous secret: %w", err)
	}
	if err := setMetadata(database, metaJWTSecret, newSecret); err != nil {
		return fmt.Errorf("store new secret: %w", err)
	}

	fmt.Println("JWT secret rotated.")
	fmt.Println("The previous secret will continue to be accepted for token validation.")
	fmt.Println("Restart the server to pick up the new secret.")
	fmt.Println("After 15 minutes (one access token lifetime), you can remove the previous secret with --clear-prev-jwt-secret")
	return nil
}

// clearPrevJWTSecret removes the previous JWT secret from the DB.
func clearPrevJWTSecret(database *db.Database) error {
	if err := deleteMetadata(database, metaJWTSecretPrev); err != nil {
		return fmt.Errorf("delete previous secret: %w", err)
	}
	fmt.Println("Previous JWT secret cleared. Restart the server to apply.")
	return nil
}

// ── metadata table helpers ───────────────────────────────────────────

func getMetadata(database *db.Database, key string) (string, error) {
	var value string
	err := database.DB().QueryRow("SELECT value FROM metadata WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func setMetadata(database *db.Database, key, value string) error {
	_, err := database.DB().Exec(
		"INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value,
	)
	return err
}

func deleteMetadata(database *db.Database, key string) error {
	_, err := database.DB().Exec("DELETE FROM metadata WHERE key = ?", key)
	return err
}

func generateSecret(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
