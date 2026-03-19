package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/httputil"
	"github.com/sweeney/identity/internal/service"
)

type webauthnHandler struct {
	svc        service.WebAuthnServicer
	trustProxy string
}

// --- Registration ---

func (h *webauthnHandler) registerBegin(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())

	creation, challengeID, err := h.svc.BeginRegistration(claims.UserID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrWebAuthnNotEnabled):
			jsonError(w, http.StatusBadRequest, "webauthn_not_enabled", "passkeys are not enabled on this server")
		case errors.Is(err, service.ErrWebAuthnCredentialLimitReached):
			jsonError(w, http.StatusConflict, "webauthn_credential_limit", "maximum number of passkeys reached")
		default:
			jsonError(w, http.StatusInternalServerError, "internal_error", "failed to begin passkey registration")
		}
		return
	}

	jsonOK(w, map[string]any{
		"publicKey":    creation.Response,
		"challenge_id": challengeID,
	})
}

// headerOrQuery reads a value from the request header first, falling back to query param.
func headerOrQuery(r *http.Request, header, query string) string {
	if v := r.Header.Get(header); v != "" {
		return v
	}
	return r.URL.Query().Get(query)
}

func (h *webauthnHandler) registerFinish(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())

	challengeID := headerOrQuery(r, "X-Challenge-ID", "challenge_id")
	name := headerOrQuery(r, "X-Passkey-Name", "name")

	if challengeID == "" {
		jsonError(w, http.StatusBadRequest, "validation_error", "challenge_id is required")
		return
	}

	cred, err := h.svc.FinishRegistration(claims.UserID, challengeID, name, r)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrWebAuthnNotEnabled):
			jsonError(w, http.StatusBadRequest, "webauthn_not_enabled", "passkeys are not enabled on this server")
		case errors.Is(err, service.ErrWebAuthnInvalidChallenge):
			jsonError(w, http.StatusBadRequest, "webauthn_invalid_challenge", "challenge expired or not found")
		case errors.Is(err, service.ErrWebAuthnVerificationFailed):
			jsonError(w, http.StatusBadRequest, "webauthn_verification_failed", "passkey registration verification failed")
		default:
			jsonError(w, http.StatusInternalServerError, "internal_error", "failed to complete passkey registration")
		}
		return
	}

	jsonCreated(w, toCredentialResponse(cred))
}

// --- Authentication ---

type loginBeginRequest struct {
	Username string `json:"username"`
}

func (h *webauthnHandler) loginBegin(w http.ResponseWriter, r *http.Request) {
	var req loginBeginRequest
	if body, _ := io.ReadAll(r.Body); len(body) > 0 {
		if err := json.NewDecoder(bytes.NewReader(body)).Decode(&req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid_request_body", "request body must be JSON")
			return
		}
	}

	assertion, challengeID, err := h.svc.BeginLogin(req.Username)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrWebAuthnNotEnabled):
			jsonError(w, http.StatusBadRequest, "webauthn_not_enabled", "passkeys are not enabled on this server")
		default:
			jsonError(w, http.StatusInternalServerError, "internal_error", "failed to begin passkey login")
		}
		return
	}

	jsonOK(w, map[string]any{
		"publicKey":    assertion.Response,
		"challenge_id": challengeID,
	})
}

func (h *webauthnHandler) loginFinish(w http.ResponseWriter, r *http.Request) {
	challengeID := headerOrQuery(r, "X-Challenge-ID", "challenge_id")
	deviceHint := ""

	if challengeID == "" {
		jsonError(w, http.StatusBadRequest, "validation_error", "challenge_id query parameter is required")
		return
	}

	result, err := h.svc.FinishLogin(challengeID, r, deviceHint, httputil.ExtractClientIP(r, h.trustProxy))
	if err != nil {
		switch {
		case errors.Is(err, service.ErrWebAuthnNotEnabled):
			jsonError(w, http.StatusBadRequest, "webauthn_not_enabled", "passkeys are not enabled on this server")
		case errors.Is(err, service.ErrWebAuthnInvalidChallenge):
			jsonError(w, http.StatusBadRequest, "webauthn_invalid_challenge", "challenge expired or not found")
		case errors.Is(err, service.ErrWebAuthnVerificationFailed):
			jsonError(w, http.StatusUnauthorized, "webauthn_verification_failed", "passkey authentication failed")
		case errors.Is(err, service.ErrAccountDisabled):
			jsonError(w, http.StatusForbidden, "account_disabled", "account has been disabled")
		default:
			jsonError(w, http.StatusInternalServerError, "internal_error", "failed to complete passkey login")
		}
		return
	}

	jsonOK(w, loginResponse{
		AccessToken:  result.AccessToken,
		TokenType:    result.TokenType,
		ExpiresIn:    result.ExpiresIn,
		RefreshToken: result.RefreshToken,
	})
}

// --- Credential Management ---

type credentialResponse struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

func toCredentialResponse(c *domain.WebAuthnCredential) credentialResponse {
	return credentialResponse{
		ID:         c.ID,
		Name:       c.Name,
		CreatedAt:  c.CreatedAt,
		LastUsedAt: c.LastUsedAt,
	}
}

func (h *webauthnHandler) listCredentials(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())

	creds, err := h.svc.ListCredentials(claims.UserID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal_error", "failed to list passkeys")
		return
	}

	resp := make([]credentialResponse, len(creds))
	for i, c := range creds {
		resp[i] = toCredentialResponse(c)
	}

	jsonOK(w, map[string]any{
		"credentials": resp,
		"total":       len(resp),
	})
}

type renameCredentialRequest struct {
	Name string `json:"name"`
}

func (h *webauthnHandler) renameCredential(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	credID := r.PathValue("id")

	var req renameCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}

	err := h.svc.RenameCredential(claims.UserID, credID, req.Name)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrWebAuthnCredentialNotFound):
			jsonError(w, http.StatusNotFound, "webauthn_credential_not_found", "passkey not found")
		default:
			jsonError(w, http.StatusInternalServerError, "internal_error", "failed to rename passkey")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *webauthnHandler) deleteCredential(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	credID := r.PathValue("id")

	err := h.svc.DeleteCredential(claims.UserID, credID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrWebAuthnCredentialNotFound):
			jsonError(w, http.StatusNotFound, "webauthn_credential_not_found", "passkey not found")
		default:
			jsonError(w, http.StatusInternalServerError, "internal_error", "failed to delete passkey")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
