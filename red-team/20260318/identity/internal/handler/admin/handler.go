package admin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/service"
	"github.com/sweeney/identity/internal/ui"
)

// tmplSet wraps the base template and clones it per render to allow each page
// to independently define {{block}} overrides without polluting a shared set.
type tmplSet struct {
	base  *template.Template
	funcs template.FuncMap
}

func (ts *tmplSet) render(w http.ResponseWriter, page string, data any) error {
	cloned, err := ts.base.Clone()
	if err != nil {
		return err
	}
	if _, err := cloned.New(page).Funcs(ts.funcs).ParseFS(ui.TemplateFS, "templates/"+page); err != nil {
		return err
	}
	return cloned.ExecuteTemplate(w, "base.html", data)
}

const sessionCookieName = "admin_session"
const sessionTTL = 8 * time.Hour

type adminHandler struct {
	cfg          Config
	authSvc      service.AuthServicer
	userSvc      service.UserServicer
	oauthClients domain.OAuthClientRepository
	auditRepo    domain.AuditRepository
	backupSvc    domain.BackupService
	tmpl         *tmplSet
}

// --- Session management ---

func (h *adminHandler) mintSession(username string) (string, error) {
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(sessionTTL)),
		Subject:   username,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(h.cfg.SessionSecret))
}

func (h *adminHandler) validateSession(tokenStr string) bool {
	_, err := h.parseSession(tokenStr)
	return err == nil
}

// parseSession validates and returns the claims from a session token.
func (h *adminHandler) parseSession(tokenStr string) (*jwt.RegisteredClaims, error) {
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (any, error) {
			return []byte(h.cfg.SessionSecret), nil
		},
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid {
		return nil, errors.New("invalid session")
	}
	return claims, nil
}

// sessionUsername returns the username from the current session cookie, or "".
func (h *adminHandler) sessionUsername(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	claims, err := h.parseSession(cookie.Value)
	if err != nil {
		return ""
	}
	return claims.Subject
}

func (h *adminHandler) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || !h.validateSession(cookie.Value) {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *adminHandler) setSession(w http.ResponseWriter, username string) error {
	tokenStr, err := h.mintSession(username)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    tokenStr,
		Path:     "/admin",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.cfg.Production,
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func (h *adminHandler) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/admin",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cfg.Production,
		SameSite: http.SameSiteStrictMode,
	})
}

// --- CSRF protection ---

// csrfToken derives a CSRF token from the session cookie using HMAC.
// No extra state needed — the token is deterministic for a given session.
func (h *adminHandler) csrfToken(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(h.cfg.SessionSecret+"csrf"))
	mac.Write([]byte(cookie.Value))
	return hex.EncodeToString(mac.Sum(nil))
}

// requireCSRF wraps a POST handler to validate the CSRF token.
func (h *adminHandler) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			token := r.FormValue("_csrf")
			expected := h.csrfToken(r)
			if expected == "" || !hmac.Equal([]byte(token), []byte(expected)) {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- Template rendering ---

func (h *adminHandler) render(w http.ResponseWriter, r *http.Request, page string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["CSRFToken"] = h.csrfToken(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.render(w, page, data); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// --- Login / Logout ---

func (h *adminHandler) loginGet(w http.ResponseWriter, r *http.Request) {
	// Already logged in — redirect to dashboard
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil && h.validateSession(cookie.Value) {
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}
	h.render(w, r, "login.html", map[string]any{"HideNav": true})
}

func (h *adminHandler) loginPost(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	ip := r.Header.Get("CF-Connecting-IP")
	if ip == "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip = host
	}

	userID, err := h.authSvc.AuthorizeUser(username, password, ip)
	if err != nil {
		h.recordAudit(domain.EventLoginFailure, "", username, ip)
		h.render(w, r, "login.html", map[string]any{
			"HideNav":  true,
			"Error":    "Invalid credentials",
			"Username": username,
		})
		return
	}

	// Verify the user has admin role
	user, err := h.userSvc.GetByID(userID)
	if err != nil || user.Role != domain.RoleAdmin {
		h.recordAuditWithDetail(domain.EventLoginFailure, userID, username, ip, "insufficient role")
		h.render(w, r, "login.html", map[string]any{
			"HideNav":  true,
			"Error":    "Admin access required",
			"Username": username,
		})
		return
	}

	h.recordAudit(domain.EventLoginSuccess, userID, username, ip)

	if err := h.setSession(w, username); err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

func (h *adminHandler) logout(w http.ResponseWriter, r *http.Request) {
	username := h.sessionUsername(r)
	h.clearSession(w)
	ip := r.Header.Get("CF-Connecting-IP")
	if ip == "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip = host
	}
	h.recordAudit(domain.EventLogout, "", username, ip)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// --- Dashboard ---

func (h *adminHandler) dashboard(w http.ResponseWriter, r *http.Request) {
	users, _ := h.userSvc.List()
	data := map[string]any{
		"UserCount": len(users),
	}

	// Find most recent backup event
	if h.auditRepo != nil {
		events, err := h.auditRepo.List(50)
		if err == nil {
			for _, e := range events {
				if e.EventType == domain.EventBackupSuccess {
					data["LastBackupAt"] = e.OccurredAt.Format("2006-01-02 15:04:05 UTC")
					data["LastBackupAgo"] = timeAgo(e.OccurredAt)
					data["LastBackupDetail"] = e.Detail
					break
				}
			}
		}
	}

	h.render(w, r, "dashboard.html", data)
}

// --- Users List ---

func (h *adminHandler) usersList(w http.ResponseWriter, r *http.Request) {
	users, err := h.userSvc.List()
	if err != nil {
		http.Error(w, "failed to list users", http.StatusInternalServerError)
		return
	}
	h.render(w, r, "users_list.html", map[string]any{
		"Users": users,
	})
}

// --- Create User ---

func (h *adminHandler) usersNewGet(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "user_form.html", map[string]any{
		"FormAction":         "/admin/users/new",
		"SelectedRole":       "user",
		"MinPasswordLength":  auth.MinPasswordLength,
	})
}

func (h *adminHandler) usersNewPost(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	displayName := r.FormValue("display_name")
	password := r.FormValue("password")
	roleStr := r.FormValue("role")

	if username == "" || password == "" {
		h.render(w, r, "user_form.html", map[string]any{
			"FormAction":        "/admin/users/new",
			"Error":             "Username and password are required",
			"FormUsername":      username,
			"FormDisplayName":   displayName,
			"SelectedRole":      roleStr,
			"MinPasswordLength": auth.MinPasswordLength,
		})
		return
	}

	role := domain.RoleUser
	if roleStr == string(domain.RoleAdmin) {
		role = domain.RoleAdmin
	}

	_, err := h.userSvc.Create(username, displayName, password, role, h.auditMeta(r))
	if err != nil {
		h.render(w, r, "user_form.html", map[string]any{
			"FormAction":        "/admin/users/new",
			"Error":             userFacingError(err),
			"FormUsername":      username,
			"FormDisplayName":   displayName,
			"SelectedRole":      roleStr,
			"MinPasswordLength": auth.MinPasswordLength,
		})
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// --- Edit User ---

func (h *adminHandler) usersEditGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, err := h.userSvc.GetByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.render(w, r, "user_form.html", map[string]any{
		"FormAction":        "/admin/users/" + id + "/edit",
		"User":              user,
		"SelectedRole":      string(user.Role),
		"MinPasswordLength": auth.MinPasswordLength,
	})
}

func (h *adminHandler) usersEditPost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	input := service.UpdateUserInput{}
	if dn := r.FormValue("display_name"); dn != "" {
		input.DisplayName = &dn
	}
	if pw := r.FormValue("password"); pw != "" {
		input.Password = &pw
	}
	if roleStr := r.FormValue("role"); roleStr != "" {
		role := domain.Role(roleStr)
		input.Role = &role
	}
	isActive := r.FormValue("is_active") == "1"
	input.IsActive = &isActive

	user, err := h.userSvc.GetByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	_, err = h.userSvc.Update(id, input, h.auditMeta(r))
	if err != nil {
		h.render(w, r, "user_form.html", map[string]any{
			"FormAction":        "/admin/users/" + id + "/edit",
			"User":              user,
			"SelectedRole":      string(user.Role),
			"MinPasswordLength": auth.MinPasswordLength,
			"Error":             userFacingError(err),
		})
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// --- Delete User ---

func (h *adminHandler) usersDeleteGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, err := h.userSvc.GetByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.render(w, r, "confirm_delete.html", map[string]any{"User": user})
}

func (h *adminHandler) usersDeletePost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.userSvc.Delete(id, h.auditMeta(r)); err != nil {
		log.Printf("admin ui error: %v", err)
		http.Error(w, "An unexpected error occurred.", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// --- Backup ---

func (h *adminHandler) triggerBackup(w http.ResponseWriter, r *http.Request) {
	if h.backupSvc != nil {
		h.backupSvc.TriggerAsync()
	}
	http.Redirect(w, r, "/admin/?flash=backup_triggered", http.StatusSeeOther)
}

// --- OAuth Clients ---

func (h *adminHandler) oauthList(w http.ResponseWriter, r *http.Request) {
	clients, err := h.oauthClients.List()
	if err != nil {
		http.Error(w, "failed to list clients", http.StatusInternalServerError)
		return
	}
	h.render(w, r, "oauth_clients_list.html", map[string]any{
		"Clients": clients,
	})
}

func (h *adminHandler) oauthNewGet(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "oauth_client_form.html", map[string]any{
		"FormAction": "/admin/oauth/new",
	})
}

func (h *adminHandler) oauthNewPost(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.FormValue("id"))
	name := strings.TrimSpace(r.FormValue("name"))
	rawURIs := r.FormValue("redirect_uris")

	if id == "" || name == "" || rawURIs == "" {
		h.render(w, r, "oauth_client_form.html", map[string]any{
			"FormAction":       "/admin/oauth/new",
			"Error":            "Client ID, name, and at least one redirect URI are required.",
			"FormID":           id,
			"FormName":         name,
			"FormRedirectURIs": rawURIs,
		})
		return
	}

	uris := splitURIs(rawURIs)
	now := time.Now().UTC()
	client := &domain.OAuthClient{
		ID:           id,
		Name:         name,
		RedirectURIs: uris,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := h.oauthClients.Create(client); err != nil {
		h.render(w, r, "oauth_client_form.html", map[string]any{
			"FormAction":       "/admin/oauth/new",
			"Error":            userFacingError(err),
			"FormID":           id,
			"FormName":         name,
			"FormRedirectURIs": rawURIs,
		})
		return
	}
	http.Redirect(w, r, "/admin/oauth", http.StatusSeeOther)
}

func (h *adminHandler) oauthEditGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	client, err := h.oauthClients.GetByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.render(w, r, "oauth_client_form.html", map[string]any{
		"FormAction": "/admin/oauth/" + id + "/edit",
		"Client":     client,
	})
}

func (h *adminHandler) oauthEditPost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	client, err := h.oauthClients.GetByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	rawURIs := r.FormValue("redirect_uris")

	if name == "" || rawURIs == "" {
		h.render(w, r, "oauth_client_form.html", map[string]any{
			"FormAction": "/admin/oauth/" + id + "/edit",
			"Client":     client,
			"Error":      "Name and at least one redirect URI are required.",
		})
		return
	}

	client.Name = name
	client.RedirectURIs = splitURIs(rawURIs)
	if err := h.oauthClients.Update(client); err != nil {
		h.render(w, r, "oauth_client_form.html", map[string]any{
			"FormAction": "/admin/oauth/" + id + "/edit",
			"Client":     client,
			"Error":      userFacingError(err),
		})
		return
	}
	http.Redirect(w, r, "/admin/oauth", http.StatusSeeOther)
}

func (h *adminHandler) oauthDeleteGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	client, err := h.oauthClients.GetByID(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.render(w, r, "confirm_delete.html", map[string]any{
		"Client":     client,
		"DeletePath": "/admin/oauth/" + id + "/delete",
		"CancelPath": "/admin/oauth",
		"ItemName":   "OAuth client " + client.Name,
	})
}

func (h *adminHandler) oauthDeletePost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.oauthClients.Delete(id); err != nil {
		log.Printf("admin ui error: %v", err)
		http.Error(w, "An unexpected error occurred.", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/oauth", http.StatusSeeOther)
}

// --- Audit Log ---

const auditLogLimit = 200

func (h *adminHandler) auditLog(w http.ResponseWriter, r *http.Request) {
	filterUserID := r.URL.Query().Get("user_id")
	filterEventType := r.URL.Query().Get("event_type")

	var events []*domain.AuthEvent
	var err error

	if filterUserID != "" {
		events, err = h.auditRepo.ListForUser(filterUserID, auditLogLimit)
	} else {
		events, err = h.auditRepo.List(auditLogLimit)
	}
	if err != nil {
		http.Error(w, "failed to load audit log", http.StatusInternalServerError)
		return
	}

	// Filter by event type client-side (simple filter)
	if filterEventType != "" {
		var filtered []*domain.AuthEvent
		for _, e := range events {
			if e.EventType == filterEventType {
				filtered = append(filtered, e)
			}
		}
		events = filtered
	}

	h.render(w, r, "audit_log.html", map[string]any{
		"Events":          events,
		"FilterUserID":    filterUserID,
		"FilterEventType": filterEventType,
	})
}

// splitURIs splits a newline-separated list of URIs into a slice, trimming whitespace.
func splitURIs(raw string) []string {
	var uris []string
	for _, line := range strings.Split(raw, "\n") {
		if u := strings.TrimSpace(line); u != "" {
			uris = append(uris, u)
		}
	}
	return uris
}

// userFacingError maps service/domain errors to safe messages for the admin UI.
func userFacingError(err error) string {
	switch {
	case errors.Is(err, domain.ErrConflict):
		return "A user with that username already exists."
	case errors.Is(err, domain.ErrNotFound):
		return "Not found."
	case errors.Is(err, domain.ErrUserLimitReached):
		return "Maximum number of users reached."
	case errors.Is(err, service.ErrWeakPassword):
		return "Password is too weak. Please use a longer password."
	case errors.Is(err, service.ErrCannotDeleteLastAdmin):
		return "Cannot delete the last admin user."
	default:
		log.Printf("admin ui error: %v", err)
		return "An unexpected error occurred."
	}
}

// recordAudit writes an audit event for admin UI actions (best-effort).
func (h *adminHandler) recordAudit(eventType, userID, username, ip string) {
	h.recordAuditWithDetail(eventType, userID, username, ip, "admin UI")
}

func (h *adminHandler) recordAuditWithDetail(eventType, userID, username, ip, detail string) {
	if h.auditRepo == nil {
		return
	}
	_ = h.auditRepo.Record(&domain.AuthEvent{
		ID:         uuid.New().String(),
		EventType:  eventType,
		UserID:     userID,
		Username:   username,
		IPAddress:  ip,
		Detail:     detail,
		OccurredAt: time.Now().UTC(),
	})
}

// timeAgo returns a human-readable relative time string like "2 days, 3 hours ago".
func timeAgo(t time.Time) string {
	d := time.Since(t)
	if d < time.Minute {
		return "just now"
	}

	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	var parts []string
	if days > 0 {
		if days == 1 {
			parts = append(parts, "1 day")
		} else {
			parts = append(parts, fmt.Sprintf("%d days", days))
		}
	}
	if hours > 0 {
		if hours == 1 {
			parts = append(parts, "1 hour")
		} else {
			parts = append(parts, fmt.Sprintf("%d hours", hours))
		}
	}
	if days == 0 && minutes > 0 {
		if minutes == 1 {
			parts = append(parts, "1 minute")
		} else {
			parts = append(parts, fmt.Sprintf("%d minutes", minutes))
		}
	}

	if len(parts) == 0 {
		return "just now"
	}
	return strings.Join(parts, ", ") + " ago"
}

// auditMeta builds an AuditMeta from an admin request.
func (h *adminHandler) auditMeta(r *http.Request) service.AuditMeta {
	ip := r.Header.Get("CF-Connecting-IP")
	if ip == "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip = host
	}
	return service.AuditMeta{
		ActorUsername: h.sessionUsername(r),
		IPAddress:     ip,
	}
}

// Ensure *adminHandler satisfies compile-time checks.
var _ = (*adminHandler)(nil)
var _ = time.Now
var _ = uuid.New
