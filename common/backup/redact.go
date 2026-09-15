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
// A value is removed when it is introduced by a key that names a credential
// *and* arrives in a shape a credential actually arrives in:
//
//   - `k=v`, including query-string parameters — X-Amz-Signature=...,
//     Credential=...;
//   - a quoted value, `"k":"v"` or its escaped form `\"k\":\"v\"` — the
//     credentials JSON of the provider chain, with or without a layer of Go
//     quoting around it;
//   - `Name: value` where the key is the *exact* name of a credential field
//     (Authorization, x-amz-security-token, SecretAccessKey, ...) and the
//     value is a single opaque run — the canonical-request and header shape.
//
// An AWS access key ID is removed wherever it appears, since it is
// recognisable on sight and needs no introducing key.
//
// Everything else is left exactly as it was, and the last of those three
// shapes is deliberately narrow, because `Name: value` is also the shape of
// every AWS error code and message. `AuthorizationQueryParametersError:
// Query-string authentication version 4 requires...` keeps its text: the key
// is not an exact credential name, and the value is prose. An endpoint that
// reports "[REDACTED]" and nothing else has traded one failure for another —
// which is why the value tests are for opaqueness rather than merely length,
// and why an authentication *scheme* (AWS4-HMAC-SHA256, Basic) survives while
// what follows it does not.
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

// secretKeyMarkers are matched as substrings against the normalised key half
// of a key/value pair — lowercased with punctuation removed, so
// "X-Amz-Security-Token", "x_amz_security_token" and "SecurityToken" all
// reduce to the same thing. A substring match is the cheap first filter; the
// bare-colon shape additionally requires an exact match from exactSecretKeys,
// because "SignatureDoesNotMatch" contains a marker and introduces a sentence.
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

// exactSecretKeys are the normalised names of fields that carry a credential
// and nothing else, so `Name: value` can be read as a header rather than as a
// diagnosis. Anything not on this list keeps its prose.
var exactSecretKeys = map[string]struct{}{
	"authorization":      {},
	"proxyauthorization": {},
	"accesskey":          {},
	"accesskeyid":        {},
	"awsaccesskeyid":     {},
	"secret":             {},
	"secretkey":          {},
	"secretaccesskey":    {},
	"awssecretaccesskey": {},
	"clientsecret":       {},
	"apikey":             {},
	"apisecret":          {},
	"password":           {},
	"passwd":             {},
	"credential":         {},
	"xamzcredential":     {},
	"signature":          {},
	"xamzsignature":      {},
	"securitytoken":      {},
	"xamzsecuritytoken":  {},
	"sessiontoken":       {},
	"xamzsessiontoken":   {},
	"awssessiontoken":    {},
}

// awsAccessKeyID matches the fixed-shape AWS/R2 key IDs: a four-character
// resource-type prefix followed by 16 uppercase alphanumerics.
var awsAccessKeyID = regexp.MustCompile(`\b(?:AKIA|ASIA|AROA|AIDA|AIPA|ANPA|ANVA|AGPA|ABIA|ACCA)[A-Z0-9]{16}\b`)

// minSecretValueLen is the shortest value worth redacting. Credentials are
// long; the first word of an English sentence following a colon is not, and
// that is the case this threshold protects.
const minSecretValueLen = 12

// redactKeyedValues rewrites the value of every key/value pair whose key names
// a credential and whose value is shaped like one.
func redactKeyedValues(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); {
		sep := s[i]
		b.WriteByte(sep)
		i++
		if sep != '=' && sep != ':' {
			continue
		}
		key := normaliseKey(keyBefore(s, i-1))
		if !hasSecretMarker(key) {
			continue
		}

		// Find the value, skipping the gap after the separator.
		j := i
		for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
			j++
		}
		start, end, ok := credentialValue(s, j, sep, key)
		if !ok {
			// Not a credential shape. Nothing is consumed, so the main loop
			// copies it verbatim — and keeps scanning inside it, which is how
			// the pairs within an Authorization header still get redacted.
			continue
		}
		// Everything between the separator and the value — the gap, an opening
		// quote, an authentication scheme — is kept as it was.
		b.WriteString(s[i:start])
		b.WriteString(Redacted)
		i = end
	}
	return b.String()
}

// credentialValue locates the span to redact for a pair whose separator is at
// sep and whose value starts at j, or reports that this pair is not carrying a
// credential.
func credentialValue(s string, j int, sep byte, key string) (start, end int, ok bool) {
	if j >= len(s) {
		return 0, 0, false
	}

	// Quoted: "v", 'v', and the escaped \"v\" that one layer of Go quoting
	// produces. A credential shape under either separator.
	if quote, width := openingQuote(s, j); quote != 0 {
		start = j + width
		end = quotedValueEnd(s, start, quote, width == 2)
		return start, end, isCredentialToken(s[start:end])
	}

	// k=v, including query-string parameters: a machine shape, not prose.
	if sep == '=' {
		end = unquotedValueEnd(s, j)
		return j, end, isCredentialToken(s[j:end])
	}

	// `Name: value`. This is also the shape of `SomeErrorCode: message`, so it
	// is only read as a header when the key is exactly a credential's name.
	if !isExactSecretKey(key) {
		return 0, 0, false
	}
	start = skipAuthScheme(s, j)
	end = lineEnd(s, start)
	return start, end, isCredentialToken(s[start:end])
}

// isCredentialToken reports whether a value is opaque enough to be a secret: a
// single unbroken run, long enough to carry one, and not an authentication
// scheme. Prose fails on the whitespace, which is what keeps an error message
// readable.
func isCredentialToken(v string) bool {
	if len(v) < minSecretValueLen || v == Redacted {
		return false
	}
	if strings.ContainsAny(v, " \t\r\n") {
		return false
	}
	return !isAuthScheme(v)
}

// isAuthScheme reports whether a value names an authentication scheme. A
// scheme says how a request was signed, not what it was signed with, and it is
// what you want to read when an endpoint or region is misconfigured.
func isAuthScheme(v string) bool {
	switch strings.ToLower(v) {
	case "basic", "bearer", "digest", "negotiate", "hoba", "mutual", "aws":
		return true
	}
	return strings.HasPrefix(strings.ToUpper(v), "AWS4-")
}

// skipAuthScheme returns the index of the credential within a header value,
// stepping over a leading scheme when one introduces something else:
// "AWS4-HMAC-SHA256 Credential=..." starts at "Credential".
func skipAuthScheme(s string, i int) int {
	end := i
	for end < len(s) && s[end] != ' ' && s[end] != '\t' && s[end] != '\r' && s[end] != '\n' {
		end++
	}
	if end == len(s) || !isAuthScheme(s[i:end]) {
		return i
	}
	for end < len(s) && (s[end] == ' ' || s[end] == '\t') {
		end++
	}
	return end
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

// openingQuote reports the quote a value is wrapped in and how many bytes
// introduce it: one for a literal quote, two for the backslash-escaped form
// that survives a round through %q.
func openingQuote(s string, i int) (quote byte, width int) {
	switch {
	case s[i] == '"' || s[i] == '\'':
		return s[i], 1
	case s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\''):
		return s[i+1], 2
	}
	return 0, 0
}

// quotedValueEnd returns the index one past a quoted value. When the value was
// opened with an escaped quote it closes with one too, so the backslash stays
// outside the value and the text reads the same after redaction.
func quotedValueEnd(s string, i int, quote byte, escaped bool) int {
	for ; i < len(s); i++ {
		if s[i] == quote {
			return i
		}
		if escaped && s[i] == '\\' && i+1 < len(s) && s[i+1] == quote {
			return i
		}
	}
	return len(s)
}

// unquotedValueEnd returns the index one past an unquoted value: the first
// delimiter that can end one.
func unquotedValueEnd(s string, i int) int {
	for ; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r', ',', ';', '&', '"', '\'', ')', '}', '>', '|':
			return i
		}
	}
	return len(s)
}

func lineEnd(s string, i int) int {
	if n := strings.IndexAny(s[i:], "\r\n"); n >= 0 {
		return i + n
	}
	return len(s)
}

// hasSecretMarker reports whether a key mentions a credential anywhere in its
// name. It is the first filter, not the decision.
func hasSecretMarker(key string) bool {
	if key == "" {
		return false
	}
	for _, marker := range secretKeyMarkers {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

// isExactSecretKey reports whether a normalised key is a credential's name
// rather than merely containing one.
func isExactSecretKey(key string) bool {
	_, ok := exactSecretKeys[key]
	return ok
}

// normaliseKey lowercases a key and drops everything that is not a letter or
// digit, so separators, quoting and one layer of backslashes cannot hide a
// marker.
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
