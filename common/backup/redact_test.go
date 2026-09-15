package backup_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sweeney/identity/common/backup"
)

// redact_test.go covers issue #45 point 4. The errors a backup surfaces are
// the AWS SDK's, which is this module's dependency rather than the consumer's,
// so the guard against handing an attacker the R2 credential belongs here
// instead of being re-guessed by every consumer that reports backup health.

func TestRedactSecrets_SigV4Error(t *testing.T) {
	const (
		keyID = "AKIAIOSFODNN7EXAMPLE"
		sig   = "6f2a1b9c4d8e7f3a2b1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a"
	)
	in := "operation error S3: PutObject, https response error StatusCode: 403, " +
		"api error SignatureDoesNotMatch: The request signature we calculated does not match. " +
		"Authorization=AWS4-HMAC-SHA256 Credential=" + keyID + "/20260915/auto/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-date, Signature=" + sig

	got := backup.RedactSecrets(in)

	assert.NotContains(t, got, keyID)
	assert.NotContains(t, got, sig)
	// What is left must still be worth reading.
	assert.Contains(t, got, "SignatureDoesNotMatch")
	assert.Contains(t, got, "StatusCode: 403")
	assert.Contains(t, got, "PutObject")
}

func TestRedactSecrets_PresignedQueryString(t *testing.T) {
	in := "get object: https://acct.r2.cloudflarestorage.com/bucket/key?" +
		"X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260915%2Fauto%2Fs3&" +
		"X-Amz-SignedHeaders=host&" +
		"X-Amz-Signature=deadbeefcafef00dfeedfacedeadbeefcafef00dfeedfacedeadbeefcafef00d"

	got := backup.RedactSecrets(in)

	assert.NotContains(t, got, "AKIAIOSFODNN7EXAMPLE")
	assert.NotContains(t, got, "deadbeefcafef00dfeedfacedeadbeefcafef00dfeedfacedeadbeefcafef00d")
	assert.Contains(t, got, "bucket/key", "the object being written is not the secret")
}

func TestRedactSecrets_JSONCredentials(t *testing.T) {
	in := `load config: {"AccessKeyId":"AKIAIOSFODNN7EXAMPLE",` +
		`"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",` +
		`"Region":"auto"}`

	got := backup.RedactSecrets(in)

	assert.NotContains(t, got, "AKIAIOSFODNN7EXAMPLE")
	assert.NotContains(t, got, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	assert.Contains(t, got, `"Region":"auto"`, "non-credential fields survive")
}

func TestRedactSecrets_HeaderForm(t *testing.T) {
	in := "Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260915, " +
		"x-amz-security-token: IQoJb3JpZ2luX2VjELL9v1AbCdEfGhIjKlMnOpQrStUv"

	got := backup.RedactSecrets(in)

	assert.NotContains(t, got, "AKIAIOSFODNN7EXAMPLE")
	assert.NotContains(t, got, "IQoJb3JpZ2luX2VjELL9v1AbCdEfGhIjKlMnOpQrStUv")
}

func TestRedactSecrets_BareAccessKeyID(t *testing.T) {
	// An access key ID is recognisable on sight, so it goes even when it is
	// not introduced by a key of its own.
	got := backup.RedactSecrets("InvalidAccessKeyId: AKIAIOSFODNN7EXAMPLE is not a known key")

	assert.NotContains(t, got, "AKIAIOSFODNN7EXAMPLE")
	assert.Contains(t, got, "InvalidAccessKeyId")
	assert.Contains(t, got, "is not a known key")

	// No introducing key at all: the shape alone is enough.
	got = backup.RedactSecrets("put object: request AKIAIOSFODNN7EXAMPLE rejected")
	assert.NotContains(t, got, "AKIAIOSFODNN7EXAMPLE")
	assert.Contains(t, got, "rejected")

	// A session key ID (ASIA prefix) too.
	got = backup.RedactSecrets("put object: ASIAY34FZKBOKMUTVV7A rejected")
	assert.NotContains(t, got, "ASIAY34FZKBOKMUTVV7A")
}

func TestRedactSecrets_LeavesProseIntact(t *testing.T) {
	// Every one of these mentions a marker word without carrying a credential.
	// Redacting them would trade a leak for an unreadable health endpoint.
	for _, in := range []string{
		"copy db: vacuum into /tmp/identity-backup-123.sqlite3: database is locked",
		"api error InvalidAccessKeyId: The AWS Access Key Id you provided does not exist in our records.",
		"api error SignatureDoesNotMatch: check your secret access key and signing method",
		"upload backup: context deadline exceeded",
		"get credentials: no EC2 IMDS role found",
	} {
		assert.Equal(t, in, backup.RedactSecrets(in), "prose without a credential value must be left alone")
	}
}

func TestRedactSecrets_EmptyAndUnmarked(t *testing.T) {
	assert.Equal(t, "", backup.RedactSecrets(""))
	assert.Equal(t, "upload backup: connection reset by peer",
		backup.RedactSecrets("upload backup: connection reset by peer"))
}

func TestRedactSecrets_PreservesTheBackupKey(t *testing.T) {
	// Backup keys are long, slash-separated and entirely unsecret. They must
	// come through a redaction untouched or the status loses its most useful
	// field.
	in := "upload backup: production/backups/identity/2026/09/15/identity-2026-09-15T03:00:00Z.sqlite3: 500"
	assert.Equal(t, in, backup.RedactSecrets(in))
}

func TestRedactSecrets_IsIdempotent(t *testing.T) {
	in := "Credential=AKIAIOSFODNN7EXAMPLE/20260915/auto/s3/aws4_request"
	once := backup.RedactSecrets(in)
	assert.Equal(t, once, backup.RedactSecrets(once))
	assert.NotEqual(t, in, once)
}

func TestRedactSecrets_CaseInsensitive(t *testing.T) {
	for _, in := range []string{
		"X-Amz-Signature=deadbeefcafef00dfeedfacedeadbeef",
		"x-amz-signature=deadbeefcafef00dfeedfacedeadbeef",
		"X-AMZ-SIGNATURE=deadbeefcafef00dfeedfacedeadbeef",
	} {
		got := backup.RedactSecrets(in)
		assert.NotContains(t, strings.ToLower(got), "deadbeefcafef00dfeedfacedeadbeef", "input: %s", in)
	}
}
