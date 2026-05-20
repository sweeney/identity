package oauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/sweeney/identity/common/httputil"
	"github.com/sweeney/identity/internal/service"
)

// deviceAuthorizationResponse is the RFC 8628 §3.2 JSON body.
type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	// ClaimCode is a non-standard echo used by the claim-code flow so the
	// device can display the sticker URL on initial pairing. It is empty for
	// standard device flow requests.
	ClaimCode string `json:"claim_code,omitempty"`
}

// deviceAuthorize handles POST /oauth/device_authorization.
func (h *oauthHandler) deviceAuthorize(w http.ResponseWriter, r *http.Request) {
	if h.deviceSvc == nil {
		oauthError(w, "unsupported_grant_type", "Device authorization is not enabled.")
		return
	}

	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request", "Could not parse form.")
		return
	}

	clientID := r.FormValue("client_id")
	scope := r.FormValue("scope")

	if clientID == "" {
		oauthError(w, "invalid_request", "client_id is required.")
		return
	}

	ip := httputil.ExtractClientIP(r, h.trustProxy)
	result, err := h.deviceSvc.IssueDeviceAuthorization(clientID, scope, ip)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUnknownClient):
			oauthError(w, "invalid_client", "Unknown client.")
		case errors.Is(err, service.ErrUnauthorizedClient):
			oauthError(w, "unauthorized_client", "Client is not authorized for device_code grant.")
		case errors.Is(err, service.ErrInvalidScope):
			oauthError(w, "invalid_scope", "Requested scope exceeds client's allowed scopes.")
		default:
			oauthError(w, "server_error", "An unexpected error occurred.")
		}
		return
	}

	jsonOK(w, deviceAuthorizationResponse{
		DeviceCode:              result.DeviceCode,
		UserCode:                result.UserCode,
		VerificationURI:         result.VerificationURI,
		VerificationURIComplete: result.VerificationURIComplete,
		ExpiresIn:               result.ExpiresIn,
		Interval:                result.Interval,
	})
}

// deviceClaim handles POST /oauth/device/claim. A device with a pre-shared
// claim_code (sticker) exchanges it for a device_code it can poll with.
func (h *oauthHandler) deviceClaim(w http.ResponseWriter, r *http.Request) {
	if h.deviceSvc == nil {
		oauthError(w, "unsupported_grant_type", "Device authorization is not enabled.")
		return
	}

	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request", "Could not parse form.")
		return
	}

	clientID := r.FormValue("client_id")
	claimCode := r.FormValue("claim_code")
	scope := r.FormValue("scope")

	if clientID == "" || claimCode == "" {
		oauthError(w, "invalid_request", "client_id and claim_code are required.")
		return
	}

	ip := httputil.ExtractClientIP(r, h.trustProxy)
	result, err := h.deviceSvc.ClaimDevice(clientID, claimCode, scope, ip)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUnknownClient):
			oauthError(w, "invalid_client", "Unknown client.")
		case errors.Is(err, service.ErrUnauthorizedClient):
			oauthError(w, "unauthorized_client", "Client is not authorized for device_code grant.")
		case errors.Is(err, service.ErrInvalidClaimCode):
			oauthError(w, "invalid_grant", "Unknown claim code.")
		case errors.Is(err, service.ErrClaimCodeRevoked):
			oauthError(w, "invalid_grant", "Claim code has been revoked.")
		case errors.Is(err, service.ErrInvalidScope):
			oauthError(w, "invalid_scope", "Requested scope exceeds client's allowed scopes.")
		default:
			oauthError(w, "server_error", "An unexpected error occurred.")
		}
		return
	}

	jsonOK(w, deviceAuthorizationResponse{
		DeviceCode:              result.DeviceCode,
		UserCode:                result.UserCode,
		VerificationURI:         result.VerificationURI,
		VerificationURIComplete: result.VerificationURIComplete,
		ExpiresIn:               result.ExpiresIn,
		Interval:                result.Interval,
		ClaimCode:               result.ClaimCode,
	})
}

// tokenDeviceCode handles the device_code grant_type on /oauth/token.
func (h *oauthHandler) tokenDeviceCode(w http.ResponseWriter, r *http.Request) {
	if h.deviceSvc == nil {
		oauthError(w, "unsupported_grant_type", "Device authorization is not enabled.")
		return
	}

	clientID := r.FormValue("client_id")
	deviceCode := r.FormValue("device_code")

	if clientID == "" || deviceCode == "" {
		oauthError(w, "invalid_request", "client_id and device_code are required.")
		return
	}

	ip := httputil.ExtractClientIP(r, h.trustProxy)
	result, err := h.deviceSvc.PollForToken(clientID, deviceCode, ip)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrDeviceAuthorizationPending):
			oauthError(w, "authorization_pending", "The user has not yet approved this device.")
		case errors.Is(err, service.ErrDeviceSlowDown):
			oauthError(w, "slow_down", "Polling too fast. Increase your polling interval by 5 seconds.")
		case errors.Is(err, service.ErrDeviceAuthorizationDenied):
			oauthError(w, "access_denied", "The user denied this device.")
		case errors.Is(err, service.ErrDeviceCodeExpired):
			oauthError(w, "expired_token", "The device_code has expired.")
		case errors.Is(err, service.ErrInvalidDeviceCode):
			oauthError(w, "invalid_grant", "Unknown or mismatched device_code.")
		case errors.Is(err, service.ErrAccountDisabled):
			oauthError(w, "access_denied", "Account is disabled.")
		default:
			oauthError(w, "server_error", "An unexpected error occurred.")
		}
		return
	}

	jsonOK(w, tokenResponse(result))
}

// deviceVerifyGet renders the verification page where the user types a user_code
// (standard flow) or arrives via QR with a pre-filled claim_code (sticker flow).
func (h *oauthHandler) deviceVerifyGet(w http.ResponseWriter, r *http.Request) {
	if h.deviceSvc == nil {
		h.renderError(w, "Not Available", "Device authorization is not enabled.")
		return
	}

	userCode := strings.TrimSpace(r.URL.Query().Get("user_code"))
	if userCode == "" {
		userCode = strings.TrimSpace(r.URL.Query().Get("code"))
	}

	data := map[string]any{
		"HideNav":  true,
		"UserCode": userCode,
	}

	if userCode != "" {
		view, err := h.deviceSvc.LookupForVerification(userCode)
		switch {
		case err == nil:
			data["Found"] = true
			if view.Client != nil {
				data["ClientName"] = view.Client.Name
			}
			if view.ClaimCode != nil {
				data["ClaimLabel"] = view.ClaimCode.Label
			}
			if view.Authorization != nil && view.Authorization.Scope != "" {
				data["Scope"] = view.Authorization.Scope
			}
		case errors.Is(err, service.ErrInvalidUserCode):
			data["Error"] = "That code is not recognised."
		case errors.Is(err, service.ErrClaimCodeRevoked):
			data["Error"] = "That claim code has been revoked."
		case errors.Is(err, service.ErrDeviceCodeExpired):
			data["Error"] = "That code has expired."
		default:
			data["Error"] = "Could not look up the code."
		}
	}

	h.render(w, "device_verify.html", data)
}

// deviceVerifyPost authenticates the user with username+password and approves
// (or denies) the session in one POST, matching the existing /oauth/authorize
// flow style. Returns JSON for XHR callers, HTML otherwise.
func (h *oauthHandler) deviceVerifyPost(w http.ResponseWriter, r *http.Request) {
	if h.deviceSvc == nil || h.authSvc == nil {
		h.renderError(w, "Not Available", "Device authorization is not enabled.")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderError(w, "Bad Request", "Could not parse form.")
		return
	}

	userCode := strings.TrimSpace(r.FormValue("user_code"))
	username := r.FormValue("username")
	password := r.FormValue("password")
	action := r.FormValue("action") // "approve" or "deny"

	if userCode == "" {
		h.renderError(w, "Bad Request", "user_code is required.")
		return
	}

	ip := httputil.ExtractClientIP(r, h.trustProxy)

	if action == "deny" {
		if err := h.deviceSvc.Deny(userCode, ip); err != nil {
			h.renderDeviceFailure(w, userCode, "Could not record denial.")
			return
		}
		h.render(w, "device_verify_done.html", map[string]any{
			"HideNav": true,
			"Denied":  true,
		})
		return
	}

	userID, authErr := h.authSvc.AuthorizeUser(username, password, ip)
	if authErr != nil {
		errMsg := "Invalid username or password."
		if errors.Is(authErr, service.ErrAccountDisabled) {
			errMsg = "Account is disabled."
		}
		h.renderDeviceFailure(w, userCode, errMsg)
		return
	}

	if err := h.deviceSvc.Approve(userCode, userID, username, ip); err != nil {
		switch {
		case errors.Is(err, service.ErrDeviceCodeExpired):
			h.renderDeviceFailure(w, userCode, "That code has expired.")
		case errors.Is(err, service.ErrInvalidUserCode):
			h.renderDeviceFailure(w, userCode, "That code is not recognised.")
		case errors.Is(err, service.ErrClaimCodeRevoked):
			h.renderDeviceFailure(w, userCode, "That claim code has been revoked.")
		default:
			h.renderDeviceFailure(w, userCode, "Could not approve the request.")
		}
		return
	}

	h.render(w, "device_verify_done.html", map[string]any{
		"HideNav":  true,
		"Approved": true,
	})
}

func (h *oauthHandler) renderDeviceFailure(w http.ResponseWriter, userCode, msg string) {
	h.render(w, "device_verify.html", map[string]any{
		"HideNav":  true,
		"UserCode": userCode,
		"Found":    true,
		"Error":    msg,
	})
}

// Unused but referenced in handler.go — keep this package's json encoder happy.
var _ = json.Marshal
