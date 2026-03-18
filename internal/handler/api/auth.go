package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/httputil"
	"github.com/sweeney/identity/internal/service"
)

type authHandler struct {
	svc        service.AuthServicer
	trustProxy string
}

type loginRequest struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	DeviceHint string `json:"device_hint"`
}

type loginResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func (h *authHandler) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}

	if req.Username == "" || req.Password == "" {
		jsonError(w, http.StatusUnprocessableEntity, "validation_error", "username and password are required")
		return
	}

	result, err := h.svc.Login(req.Username, req.Password, req.DeviceHint, httputil.ExtractClientIP(r, h.trustProxy))
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			jsonError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		case errors.Is(err, service.ErrAccountDisabled):
			jsonError(w, http.StatusForbidden, "account_disabled", "account has been disabled")
		default:
			jsonError(w, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
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

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *authHandler) refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}

	if req.RefreshToken == "" {
		jsonError(w, http.StatusUnprocessableEntity, "validation_error", "refresh_token is required")
		return
	}

	result, err := h.svc.Refresh(req.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidRefreshToken):
			jsonError(w, http.StatusUnauthorized, "invalid_refresh_token", "the refresh token is invalid")
		case errors.Is(err, service.ErrTokenFamilyCompromised):
			jsonError(w, http.StatusUnauthorized, "token_family_compromised", "token reuse detected — please log in again")
		case errors.Is(err, service.ErrRefreshTokenExpired):
			jsonError(w, http.StatusUnauthorized, "token_expired", "the refresh token has expired")
		case errors.Is(err, service.ErrAccountDisabled):
			jsonError(w, http.StatusForbidden, "account_disabled", "account has been disabled")
		default:
			jsonError(w, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
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

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *authHandler) logout(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())

	var req logoutRequest
	// Ignore decode errors — refresh_token is optional
	json.NewDecoder(r.Body).Decode(&req) //nolint:errcheck

	if err := h.svc.Logout(claims.UserID, req.RefreshToken); err != nil {
		jsonError(w, http.StatusInternalServerError, "internal_error", "logout failed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type meResponse struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Role        string `json:"role"`
	IsActive    bool   `json:"is_active"`
}

func (h *authHandler) me(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	jsonOK(w, meResponse{
		ID:       claims.UserID,
		Username: claims.Username,
		Role:     string(claims.Role),
		IsActive: claims.IsActive,
	})
}

