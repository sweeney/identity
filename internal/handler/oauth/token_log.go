package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/sweeney/common/web/httputil"

	"github.com/sweeney/identity/internal/service"
)

// tokenRecorder passes a token response through while keeping its status and
// the start of its body, so a refusal can be logged after the handler is done.
type tokenRecorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

// tokenBodyKeep bounds how much of the response is kept: error bodies are a
// few dozen bytes, and success bodies are never inspected.
const tokenBodyKeep = 512

func (t *tokenRecorder) WriteHeader(code int) {
	t.status = code
	t.ResponseWriter.WriteHeader(code)
}

func (t *tokenRecorder) Write(p []byte) (int, error) {
	if t.status == 0 {
		t.status = http.StatusOK
	}
	if room := tokenBodyKeep - t.body.Len(); room > 0 && t.status >= 400 {
		t.body.Write(p[:min(len(p), room)])
	}
	return t.ResponseWriter.Write(p)
}

// tokenRequiredFields lists, per grant, the fields whose presence is worth
// reporting on a refusal. They are read with FormValue (body and query), as
// the handlers read them, so the log shows what the handler saw. Only presence
// is ever logged, never a value.
var tokenRequiredFields = map[string][]string{
	"authorization_code":        {"client_id", "code", "redirect_uri", "code_verifier"},
	"refresh_token":             {"client_id", "refresh_token"},
	"client_credentials":        {"client_id"},
	service.GrantTypeDeviceCode: {"client_id", "device_code"},
}

// Routine device-flow polling answers; a device polls every few seconds, so
// logging these would bury everything else.
var tokenQuietErrors = map[string]bool{
	"authorization_pending": true,
	"slow_down":             true,
}

// logTokenRefusal writes one line for a refused token request: which grant,
// which client and how it was named, how the client authenticated, which
// required fields were present, and who called. It never logs a secret, code,
// verifier or token. Every caller-supplied value is quoted with %q and
// bounded, so it cannot forge further log lines.
func (h *oauthHandler) logTokenRefusal(r *http.Request, rec *tokenRecorder) {
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.body.Bytes(), &body)
	if tokenQuietErrors[body.Error] {
		return
	}

	grantType := r.FormValue("grant_type")
	bodyClient := r.FormValue("client_id")

	auth := "none"
	basicClient := ""
	if creds, ok := extractClientCredentials(r); ok {
		auth = creds.Method
		if creds.Method == "client_secret_basic" {
			basicClient = creds.ClientID
		}
	} else if strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
		auth = "basic_malformed"
	}

	client, via := bodyClient, "body"
	switch {
	case bodyClient != "" && basicClient != "":
		via = "body+basic"
	case basicClient != "":
		client, via = basicClient, "basic"
	case bodyClient == "":
		via = "none"
	}

	fields := make([]string, 0, 4)
	for _, f := range tokenRequiredFields[grantType] {
		mark := "-"
		if r.FormValue(f) != "" {
			mark = "+"
		}
		fields = append(fields, f+":"+mark)
	}

	log.Printf("oauth: token refused status=%d error=%q grant_type=%q client=%q client_via=%s auth=%s fields=%s ip=%q ua=%q",
		rec.status, bound(body.Error, 64), bound(grantType, 100), bound(client, 100), via, auth,
		strings.Join(fields, ","), httputil.ExtractClientIP(r, h.trustProxy), bound(r.UserAgent(), 200))
}

// bound cuts a caller-supplied value to n bytes for logging.
func bound(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + fmt.Sprintf("…(%d bytes)", len(s))
}
