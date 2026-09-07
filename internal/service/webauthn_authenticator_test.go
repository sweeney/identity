package service_test

// webauthn_authenticator_test.go provides a minimal software authenticator so
// tests can drive a complete WebAuthn assertion ceremony end to end. Without
// one, no test could assert that a passkey login actually *succeeds* — only
// that its error paths error — which is how a permanently-broken login path
// reached production (WP12 / GHSA-9795-969v-64m8).
//
// It implements only what an assertion needs: an ES256 key pair, a COSE-encoded
// public key to store as the credential, and a signature over
// authenticatorData || SHA-256(clientDataJSON), per WebAuthn §6.3.3.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/domain"
)

// softAuthenticator is a test-only WebAuthn authenticator holding one credential.
type softAuthenticator struct {
	key          *ecdsa.PrivateKey
	credentialID []byte
	userID       string
	signCount    uint32
}

func newSoftAuthenticator(t *testing.T, userID string) *softAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	credID := make([]byte, 32)
	_, err = rand.Read(credID)
	require.NoError(t, err)
	return &softAuthenticator{key: key, credentialID: credID, userID: userID}
}

// coseKey encodes the public key as a COSE_Key ES256 structure, the format a
// browser hands over at registration and the one stored in the credential row.
//
//	{1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
//
// Hand-encoded rather than pulled through a CBOR library so the test does not
// add a dependency to encode five fixed map entries.
func (a *softAuthenticator) coseKey() []byte {
	x := make([]byte, 32)
	y := make([]byte, 32)
	a.key.PublicKey.X.FillBytes(x)
	a.key.PublicKey.Y.FillBytes(y)

	out := []byte{
		0xa5,       // map(5)
		0x01, 0x02, // 1: 2
		0x03, 0x26, // 3: -7
		0x20, 0x01, // -1: 1
		0x21, 0x58, 0x20, // -2: bytes(32)
	}
	out = append(out, x...)
	out = append(out, 0x22, 0x58, 0x20) // -3: bytes(32)
	out = append(out, y...)
	return out
}

// credential builds the stored credential row for this authenticator.
func (a *softAuthenticator) credential() *domain.WebAuthnCredential {
	return &domain.WebAuthnCredential{
		ID:              "cred-row-" + a.userID,
		UserID:          a.userID,
		CredentialID:    a.credentialID,
		PublicKey:       a.coseKey(),
		AttestationType: "none",
		Name:            "Test Passkey",
		UserPresent:     true,
		UserVerified:    true,
		SignCount:       a.signCount,
	}
}

// assertionRequest builds the HTTP request that loginFinish would receive from
// a browser after navigator.credentials.get() resolved against `challenge`.
func (a *softAuthenticator) assertionRequest(t *testing.T, challenge, rpID, origin string) *http.Request {
	t.Helper()

	clientData, err := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})
	require.NoError(t, err)

	// authenticatorData: rpIDHash(32) || flags(1) || signCount(4).
	// Flags UP|UV — user present and verified.
	rpIDHash := sha256.Sum256([]byte(rpID))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, 0x01|0x04)
	a.signCount++
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], a.signCount)
	authData = append(authData, counter[:]...)

	// The signature covers authenticatorData || SHA-256(clientDataJSON).
	clientDataHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	require.NoError(t, err)

	b64 := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{
		"id":    b64(a.credentialID),
		"rawId": b64(a.credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"authenticatorData": b64(authData),
			"signature":         b64(sig),
			"userHandle":        b64([]byte(a.userID)),
		},
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "/api/v1/webauthn/login/finish", strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	return req
}
