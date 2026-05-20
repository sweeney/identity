package admin

import (
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/common/httputil"
	"github.com/sweeney/identity/internal/service"
)

// claimCodesList renders the list of claim codes for a given OAuth client.
// Raw codes are never shown here — only at generation time. A "generate more"
// button links to the form, and each code has a "revoke" button.
func (h *adminHandler) claimCodesList(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("id")
	client, err := h.oauthClients.GetByID(clientID)
	if err != nil {
		http.Error(w, "unknown client", http.StatusNotFound)
		return
	}
	if !client.HasGrantType(domain.GrantTypeDeviceCode) {
		h.render(w, r, "claim_codes_list.html", map[string]any{
			"Client":            client,
			"MissingGrantType":  true,
		})
		return
	}

	codes, err := h.deviceSvc.ListClaimCodes(clientID)
	if err != nil {
		http.Error(w, "could not list claim codes", http.StatusInternalServerError)
		return
	}

	h.render(w, r, "claim_codes_list.html", map[string]any{
		"Client": client,
		"Codes":  codes,
	})
}

// claimCodesNewGet renders the "generate claim codes" form.
func (h *adminHandler) claimCodesNewGet(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("id")
	client, err := h.oauthClients.GetByID(clientID)
	if err != nil {
		http.Error(w, "unknown client", http.StatusNotFound)
		return
	}
	if !client.HasGrantType(domain.GrantTypeDeviceCode) {
		http.Error(w, "client does not have device_code grant", http.StatusBadRequest)
		return
	}
	h.render(w, r, "claim_codes_new.html", map[string]any{
		"Client": client,
	})
}

// claimCodesGenerate processes the generate form, creates claim codes, and
// renders the printable stickers page with the raw codes + QR codes. The raw
// codes are only available in this response — losing the page means losing
// the codes.
func (h *adminHandler) claimCodesGenerate(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("id")
	client, err := h.oauthClients.GetByID(clientID)
	if err != nil {
		http.Error(w, "unknown client", http.StatusNotFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	rawLabels := r.FormValue("labels")
	labels := splitLabels(rawLabels)
	if len(labels) == 0 {
		h.render(w, r, "claim_codes_new.html", map[string]any{
			"Client": client,
			"Error":  "Enter at least one label (one per line).",
		})
		return
	}
	if len(labels) > 50 {
		h.render(w, r, "claim_codes_new.html", map[string]any{
			"Client": client,
			"Error":  "Generate at most 50 claim codes at a time.",
		})
		return
	}

	ip := httputil.ExtractClientIP(r, h.cfg.TrustProxy)
	results, err := h.deviceSvc.CreateClaimCodes(clientID, labels, ip)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUnauthorizedClient):
			h.render(w, r, "claim_codes_new.html", map[string]any{
				"Client": client,
				"Error":  "This client is not configured for the device_code grant. Enable it in client settings first.",
			})
		default:
			h.render(w, r, "claim_codes_new.html", map[string]any{
				"Client": client,
				"Error":  "Could not generate claim codes: " + err.Error(),
			})
		}
		return
	}

	base := h.verificationBaseURL()
	stickers := make([]map[string]any, 0, len(results))
	for _, r := range results {
		url := base + "/oauth/device?code=" + r.RawCode
		qr, err := qrSVG(url, 220)
		if err != nil {
			http.Error(w, "qr render: "+err.Error(), http.StatusInternalServerError)
			return
		}
		stickers = append(stickers, map[string]any{
			"Label":   r.Label,
			"RawCode": r.RawCode,
			"URL":     url,
			"QR":      qr,
		})
	}

	h.render(w, r, "claim_codes_stickers.html", map[string]any{
		"Client":   client,
		"Stickers": stickers,
	})
}

// claimCodeRevoke revokes a claim code in-place and redirects back to the
// list page.
func (h *adminHandler) claimCodeRevoke(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("id")
	claimID := r.PathValue("claimID")

	ip := httputil.ExtractClientIP(r, h.cfg.TrustProxy)
	if err := h.deviceSvc.RevokeClaimCode(claimID, ip); err != nil && !errors.Is(err, service.ErrInvalidClaimCode) {
		http.Error(w, "could not revoke: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/oauth/"+clientID+"/claim-codes", http.StatusSeeOther)
}

// claimCodeDelete permanently removes a revoked claim code.
func (h *adminHandler) claimCodeDelete(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("id")
	claimID := r.PathValue("claimID")

	ip := httputil.ExtractClientIP(r, h.cfg.TrustProxy)
	if err := h.deviceSvc.DeleteClaimCode(claimID, ip); err != nil && !errors.Is(err, service.ErrInvalidClaimCode) {
		http.Error(w, "could not delete: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/oauth/"+clientID+"/claim-codes", http.StatusSeeOther)
}

// verificationBaseURL returns the external scheme+host to put in claim-code
// QR stickers. Derived from the TokenIssuer (which was pinned at startup) so
// a spoofed Host header cannot poison the stickers.
func (h *adminHandler) verificationBaseURL() string {
	if h.tokenIssuer != nil {
		return strings.TrimRight(h.tokenIssuer.Issuer(), "/")
	}
	return ""
}

// splitLabels splits a newline-separated list of labels, trimming whitespace
// and dropping blanks. Duplicates are allowed — admins may legitimately want
// two stickers labelled the same.
func splitLabels(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

// Keep html/template reachable from this file for consistent imports across
// the admin package even if all inline uses move to other files.
var _ = template.HTML("")
