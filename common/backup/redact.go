package backup

import (
	"regexp"
	"strings"
)

// Redacted is what RedactSecrets leaves in place of a credential-shaped value.
const Redacted = "[REDACTED]"

// RedactSecrets removes credential-shaped values from text that is about to be
// surfaced — a health endpoint, an audit record, a log line.
//
// The errors a backup produces come from the AWS SDK, which is this module's
// dependency rather than the consumer's, so the guard belongs here: every
// consumer that reports backup health otherwise has to guess at the same list
// of markers, and an R2 credential in a 200 response is a worse outcome than
// the failed upload it describes.
//
// Two things are removed:
//
//   - the value of a key/value pair whose key names a credential
//     (Authorization, Credential, Signature, SecretAccessKey,
//     x-amz-security-token, ...), in `k=v`, `k: v`, `"k":"v"` and query-string
//     form, when the value is long enough to be one;
//   - an AWS access key ID anywhere in the text, which is recognisable on
//     sight and so needs no introducing key.
//
// Everything else is left exactly as it was. Prose that merely mentions a
// marker word keeps its diagnosis — "InvalidAccessKeyId: The AWS Access Key Id
// you provided does not exist" comes through whole — because a health endpoint
// reporting "[REDACTED]" and nothing else has traded one failure for another.
//
// This is a guard, not a proof: it recognises the shapes credentials actually
// arrive in, and cannot promise that no future SDK error carries a secret in
// some other shape. Errors returned from RunNow are deliberately left
// untouched; the Manager redacts what it surfaces itself (Status.LastError,
// EventRecorder details and its own log output), and a caller that forwards a
// returned error somewhere public should pass it through here.
func RedactSecrets(s string) string {
	if s == "" {
		return s
	}
	return awsAccessKeyID.ReplaceAllString(redactKeyedValues(s), Redacted)
}

// secretKeyMarkers are matched against the normalised key half of a key/value
// pair — lowercased with punctuation removed, so "X-Amz-Security-Token",
// "x_amz_security_token" and "SecurityToken" all reduce to the same thing.
var secretKeyMarkers = []string{
	"secret",
	"accesskey",
	"credential",
	"authorization",
	"signature",
	"securitytoken",
	"sessiontoken",
	"apikey",
	"password",
	"passwd",
}

// awsAccessKeyID matches the fixed-shape AWS/R2 key IDs: a four-character
// resource-type prefix followed by 16 uppercase alphanumerics.
var awsAccessKeyID = regexp.MustCompile(`\b(?:AKIA|ASIA|AROA|AIDA|AIPA|ANPA|ANVA|AGPA|ABIA|ACCA)[A-Z0-9]{16}\b`)

// minSecretValueLen is the shortest value worth redacting. Credentials are
// long; the first word of an English sentence following a colon is not, and
// that is the case this threshold protects.
const minSecretValueLen = 12

// redactKeyedValues rewrites the value of every key/value pair whose key names
// a credential.
func redactKeyedValues(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); {
		c := s[i]
		b.WriteByte(c)
		i++
		if c != '=' && c != ':' {
			continue
		}
		if !isSecretKey(keyBefore(s, i-1)) {
			continue
		}
		// Preserve the gap between the separator and the value.
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			b.WriteByte(s[i])
			i++
		}
		if i == len(s) {
			break
		}

		var quote byte
		if s[i] == '"' || s[i] == '\'' {
			quote = s[i]
			b.WriteByte(quote)
			i++
		}
		end := valueEnd(s, i, quote)
		value := s[i:end]
		switch {
		case len(value) >= minSecretValueLen && value != Redacted:
			b.WriteString(Redacted)
		default:
			b.WriteString(value)
		}
		i = end
	}
	return b.String()
}

// keyBefore returns the text immediately preceding the separator at index sep,
// back to the nearest boundary: the key half of the pair, punctuation and all.
func keyBefore(s string, sep int) string {
	start := sep
	for start > 0 && !isKeyBoundary(s[start-1]) {
		start--
	}
	return s[start:sep]
}

func isKeyBoundary(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '&', '?', ',', ';', '{', '[', '(', '<', '=', ':', '/':
		return true
	}
	return false
}

// valueEnd returns the index one past the end of the value starting at i. A
// quoted value ends at its closing quote; an unquoted one at the first
// delimiter.
func valueEnd(s string, i int, quote byte) int {
	for ; i < len(s); i++ {
		if quote != 0 {
			if s[i] == quote {
				return i
			}
			continue
		}
		switch s[i] {
		case ' ', '\t', '\n', '\r', ',', ';', '&', '"', '\'', ')', '}', '>', '|':
			return i
		}
	}
	return len(s)
}

// isSecretKey reports whether a key names a credential.
func isSecretKey(key string) bool {
	if key == "" {
		return false
	}
	normalised := normaliseKey(key)
	for _, marker := range secretKeyMarkers {
		if strings.Contains(normalised, marker) {
			return true
		}
	}
	return false
}

// normaliseKey lowercases a key and drops everything that is not a letter or
// digit, so separators and quoting cannot hide a marker.
func normaliseKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for i := 0; i < len(key); i++ {
		switch c := key[i]; {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + ('a' - 'A'))
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			b.WriteByte(c)
		}
	}
	return b.String()
}
