package secrets

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"strings"

	commondb "github.com/sweeney/identity/common/db"
)

const (
	metaJWTKey        = "jwt_secret"
	metaJWTPrevKey    = "jwt_secret_prev"
	metaSessionSecret = "session_secret"
)

// Secrets holds the JWT signing keys and the session secret resolved on startup.
type Secrets struct {
	JWTCurrent  *ecdsa.PrivateKey
	JWTPrevious *ecdsa.PrivateKey // may be nil
	Session     string
}

// Resolve determines the JWT signing keys and session secret on startup.
// All values are generated on first run and persisted to the metadata table.
func Resolve(database *commondb.Database) (*Secrets, error) {
	s := &Secrets{}

	currentPEM, err := getMetadata(database, metaJWTKey)
	if err != nil {
		return nil, fmt.Errorf("read jwt key from db: %w", err)
	}

	if currentPEM != "" {
		s.JWTCurrent, err = parseECKey(currentPEM)
		if err != nil {
			// Only a value that is not PEM at all is the legacy HMAC secret this
			// migration exists for. A value that *is* a PEM block but will not
			// parse is corruption — a truncated or partially written row, a
			// format from a future version, a bad restore — and generating a
			// replacement would destroy the only copy of the production signing
			// key along with the rotation fallback that would have kept existing
			// tokens verifying. Fail closed and let an operator look at it.
			if !isLegacySecret(currentPEM) {
				return nil, fmt.Errorf("stored %s is not a usable EC private key: %w — "+
					"refusing to overwrite it; restore the key or clear the row deliberately",
					metaJWTKey, err)
			}
			log.Println("Migrating JWT signing key from HMAC secret to EC keypair")
			s.JWTCurrent, err = generateAndStoreKey(database)
			if err != nil {
				return nil, err
			}
			_ = deleteMetadata(database, metaJWTPrevKey)
		} else if prevPEM, _ := getMetadata(database, metaJWTPrevKey); prevPEM != "" {
			s.JWTPrevious, err = parseECKey(prevPEM)
			if err != nil {
				return nil, fmt.Errorf("parse previous jwt key: %w", err)
			}
		}
	} else {
		s.JWTCurrent, err = generateAndStoreKey(database)
		if err != nil {
			return nil, err
		}
	}

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
	s.Session = session

	return s, nil
}

// RotateJWT generates a new JWT key, moving the current one to previous.
func RotateJWT(database *commondb.Database) error {
	currentPEM, err := getMetadata(database, metaJWTKey)
	if err != nil {
		return fmt.Errorf("read current key: %w", err)
	}
	if currentPEM == "" {
		return fmt.Errorf("no existing JWT key found — run the server first")
	}

	key, err := generateKey()
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

// ClearPrevJWT removes the previous JWT key from the DB.
func ClearPrevJWT(database *commondb.Database) error {
	if err := deleteMetadata(database, metaJWTPrevKey); err != nil {
		return fmt.Errorf("delete previous key: %w", err)
	}
	fmt.Println("Previous JWT key cleared. Restart the server to apply.")
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func generateAndStoreKey(database *commondb.Database) (*ecdsa.PrivateKey, error) {
	key, err := generateKey()
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

func generateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func getMetadata(database *commondb.Database, key string) (string, error) {
	var value string
	err := database.DB().QueryRow("SELECT value FROM metadata WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func setMetadata(database *commondb.Database, key, value string) error {
	_, err := database.DB().Exec(
		"INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value,
	)
	return err
}

func deleteMetadata(database *commondb.Database, key string) error {
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

// isLegacySecret reports whether value is the pre-EC HMAC secret rather than a
// key in PEM form. The distinction decides whether an unparseable jwt_secret row
// is migrated or treated as corruption, so it is deliberately narrow: anything
// that even looks like PEM is a key, however broken.
//
// Testing for a decodable block is not enough — a half-written key has a BEGIN
// line and no END line, so it decodes to nothing while very much being a key.
func isLegacySecret(value string) bool {
	if strings.Contains(value, "-----BEGIN") {
		return false
	}
	block, _ := pem.Decode([]byte(value))
	return block == nil
}

// parseECKey accepts an EC private key in either SEC1 ("EC PRIVATE KEY") or
// PKCS#8 ("PRIVATE KEY") form. We only ever write SEC1, but a key that arrived
// by another route is a valid key and must not be mistaken for corruption.
func parseECKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("stored key is %T, want *ecdsa.PrivateKey", parsed)
	}
	return key, nil
}

func generateSecret(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
