package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/db"
)

const (
	metaJWTKey        = "jwt_secret"      // stores PEM-encoded EC private key
	metaJWTPrevKey    = "jwt_secret_prev" // stores PEM-encoded EC private key (rotation fallback)
	metaSessionSecret = "session_secret"  // stores random string for admin cookies + CSRF
)

// serverSecrets holds the JWT signing keys and the session secret.
type serverSecrets struct {
	JWTCurrent  *ecdsa.PrivateKey
	JWTPrevious *ecdsa.PrivateKey // may be nil
	Session     string
}

// resolveServerSecrets determines the JWT signing keys and session secret on startup.
// All values are generated on first run and persisted to the metadata table.
func resolveServerSecrets(database *db.Database) (*serverSecrets, error) {
	secrets := &serverSecrets{}

	// JWT signing key
	currentPEM, err := getMetadata(database, metaJWTKey)
	if err != nil {
		return nil, fmt.Errorf("read jwt key from db: %w", err)
	}

	if currentPEM != "" {
		secrets.JWTCurrent, err = parseECKey(currentPEM)
		if err != nil {
			// Migration: DB holds the old HMAC string from before the ES256 switch.
			// Generate a fresh EC key and overwrite it. Existing access tokens (HS256,
			// 15-min TTL) will be invalidated, but that's expected when changing algorithms.
			log.Println("Migrating JWT signing key from HMAC secret to EC keypair")
			secrets.JWTCurrent, err = generateAndStoreKey(database)
			if err != nil {
				return nil, err
			}
			// Drop any previous HMAC secret — it's incompatible with the new issuer.
			_ = deleteMetadata(database, metaJWTPrevKey)
		} else if prevPEM, _ := getMetadata(database, metaJWTPrevKey); prevPEM != "" {
			secrets.JWTPrevious, err = parseECKey(prevPEM)
			if err != nil {
				return nil, fmt.Errorf("parse previous jwt key: %w", err)
			}
		}
	} else {
		// First run — generate and store
		secrets.JWTCurrent, err = generateAndStoreKey(database)
		if err != nil {
			return nil, err
		}
	}

	// Session secret (for admin cookies and CSRF tokens)
	session, err := getMetadata(database, metaSessionSecret)
	if err != nil {
		return nil, fmt.Errorf("read session secret from db: %w", err)
	}
	if session == "" {
		session, err = generateSecret(64)
		if err != nil {
			return nil, fmt.Errorf("generate session secret: %w", err)
		}
		if err := setMetadata(database, metaSessionSecret, session); err != nil {
			return nil, fmt.Errorf("store session secret: %w", err)
		}
		log.Println("Generated session secret (stored in database)")
	}
	secrets.Session = session

	return secrets, nil
}

func generateAndStoreKey(database *db.Database) (*ecdsa.PrivateKey, error) {
	key, err := auth.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate jwt key: %w", err)
	}
	keyPEM, err := encodeECKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode jwt key: %w", err)
	}
	if err := setMetadata(database, metaJWTKey, keyPEM); err != nil {
		return nil, fmt.Errorf("store jwt key: %w", err)
	}
	log.Println("Generated JWT signing key (stored in database)")
	return key, nil
}

// rotateJWTSecret generates a new JWT key, moving the current one to previous.
func rotateJWTSecret(database *db.Database) error {
	currentPEM, err := getMetadata(database, metaJWTKey)
	if err != nil {
		return fmt.Errorf("read current key: %w", err)
	}
	if currentPEM == "" {
		return fmt.Errorf("no existing JWT key found — run the server first")
	}

	key, err := auth.GenerateKey()
	if err != nil {
		return fmt.Errorf("generate new key: %w", err)
	}
	newKeyPEM, err := encodeECKey(key)
	if err != nil {
		return fmt.Errorf("encode new key: %w", err)
	}

	if err := setMetadata(database, metaJWTPrevKey, currentPEM); err != nil {
		return fmt.Errorf("store previous key: %w", err)
	}
	if err := setMetadata(database, metaJWTKey, newKeyPEM); err != nil {
		return fmt.Errorf("store new key: %w", err)
	}

	fmt.Println("JWT signing key rotated.")
	fmt.Println("The previous key will continue to be accepted for token validation.")
	fmt.Println("Restart the server to pick up the new key.")
	fmt.Println("After 15 minutes (one access token lifetime), you can remove the previous key with --clear-prev-jwt-key")
	return nil
}

// clearPrevJWTSecret removes the previous JWT key from the DB.
func clearPrevJWTSecret(database *db.Database) error {
	if err := deleteMetadata(database, metaJWTPrevKey); err != nil {
		return fmt.Errorf("delete previous key: %w", err)
	}
	fmt.Println("Previous JWT key cleared. Restart the server to apply.")
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

func encodeECKey(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
}

func parseECKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func generateSecret(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
