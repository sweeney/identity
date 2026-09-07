package secrets_test

// secrets_test.go covers WP9 (GHSA-j5gf-rvw7-9xcm): Resolve treated *any* parse
// failure on a non-empty jwt_secret row as "this is a legacy HMAC secret,
// migrate it", overwrote the row with a freshly generated key, and deleted the
// rotation fallback alongside it — silently, on a startup that then reported
// success.
//
// A truncated or partially written PEM, a row restored from a future format, or
// an EC key encoded as PKCS#8 rather than SEC1 all land in that branch. The only
// copy of the production signing key is destroyed, every outstanding token stops
// verifying, and the previous key that would have kept them alive is gone too.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commondb "github.com/sweeney/identity/common/db"
	"github.com/sweeney/identity/common/secrets"
)

//go:embed testdata/migrations/*.sql
var migrationsFS embed.FS

func newSecretsDB(t *testing.T) *commondb.Database {
	t.Helper()
	database, err := commondb.OpenWithMigrations(
		filepath.Join(t.TempDir(), "secrets.db"), migrationsFS, "testdata/migrations")
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })
	return database
}

func setMeta(t *testing.T, database *commondb.Database, key, value string) {
	t.Helper()
	_, err := database.DB().Exec(
		"INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value)
	require.NoError(t, err)
}

func getMeta(t *testing.T, database *commondb.Database, key string) string {
	t.Helper()
	var v string
	err := database.DB().QueryRow("SELECT value FROM metadata WHERE key = ?", key).Scan(&v)
	if err != nil {
		return ""
	}
	return v
}

func newECKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

// newPKCS8ECKeyPEM encodes a perfectly valid EC key in PKCS#8 form. It decodes
// as a PEM block but x509.ParseECPrivateKey (SEC1 only) rejects it.
func newPKCS8ECKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// A row that is a PEM block but does not parse is corruption, not a legacy
// secret. Startup must fail rather than overwrite the key.
func TestResolve_CorruptPEMKey_FailsClosedAndPreservesKeys(t *testing.T) {
	database := newSecretsDB(t)

	corrupt := "-----BEGIN EC PRIVATE KEY-----\nZm9vYmFy\n-----END EC PRIVATE KEY-----\n"
	prev := newECKeyPEM(t)
	setMeta(t, database, "jwt_secret", corrupt)
	setMeta(t, database, "jwt_secret_prev", prev)

	_, err := secrets.Resolve(database)

	require.Error(t, err, "a corrupt signing key must abort startup, not regenerate")
	assert.Equal(t, corrupt, getMeta(t, database, "jwt_secret"),
		"the stored signing key must not be overwritten")
	assert.Equal(t, prev, getMeta(t, database, "jwt_secret_prev"),
		"the rotation fallback must not be deleted")
}

// A truncated PEM — a partial write — is the same class of corruption.
func TestResolve_TruncatedPEM_FailsClosed(t *testing.T) {
	database := newSecretsDB(t)

	full := newECKeyPEM(t)
	truncated := full[:len(full)/2]
	setMeta(t, database, "jwt_secret", truncated)

	_, err := secrets.Resolve(database)
	require.Error(t, err)
	assert.Equal(t, truncated, getMeta(t, database, "jwt_secret"))
}

// A PKCS#8-encoded EC key is a valid key in a different container. It should be
// accepted, not treated as corruption and certainly not as a legacy secret.
func TestResolve_PKCS8ECKey_Accepted(t *testing.T) {
	database := newSecretsDB(t)

	keyPEM := newPKCS8ECKeyPEM(t)
	setMeta(t, database, "jwt_secret", keyPEM)

	s, err := secrets.Resolve(database)
	require.NoError(t, err, "a PKCS#8-encoded EC key must be accepted")
	require.NotNil(t, s.JWTCurrent)
	assert.Equal(t, keyPEM, getMeta(t, database, "jwt_secret"),
		"an acceptable key must not be rewritten")
}

// Control: a value that is not PEM at all is the genuine legacy HMAC secret,
// and must still migrate to a generated EC keypair.
func TestResolve_LegacyHMACSecret_StillMigrates(t *testing.T) {
	database := newSecretsDB(t)

	setMeta(t, database, "jwt_secret", "a-legacy-hmac-secret-value-32-chars")

	s, err := secrets.Resolve(database)
	require.NoError(t, err)
	require.NotNil(t, s.JWTCurrent)
	assert.Contains(t, getMeta(t, database, "jwt_secret"), "EC PRIVATE KEY",
		"the legacy secret must be replaced by an EC keypair")
}

// Control: a healthy key and its rotation fallback both load.
func TestResolve_HealthyKeys_Load(t *testing.T) {
	database := newSecretsDB(t)

	current := newECKeyPEM(t)
	prev := newECKeyPEM(t)
	setMeta(t, database, "jwt_secret", current)
	setMeta(t, database, "jwt_secret_prev", prev)

	s, err := secrets.Resolve(database)
	require.NoError(t, err)
	require.NotNil(t, s.JWTCurrent)
	require.NotNil(t, s.JWTPrevious)
	assert.Equal(t, current, getMeta(t, database, "jwt_secret"))
	assert.NotEmpty(t, s.Session)
}
