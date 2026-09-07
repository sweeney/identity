package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sweeney/identity/common/httputil"
	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/service"
)

type userHandler struct {
	svc        service.UserServicer
	trustProxy string
}

type userResponse struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
}

func toUserResponse(u *domain.User) userResponse {
	return userResponse{
		ID:          u.ID,
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Role:        string(u.Role),
		IsActive:    u.IsActive,
		CreatedAt:   u.CreatedAt,
	}
}

func (h *userHandler) list(w http.ResponseWriter, r *http.Request) {
	users, err := h.svc.List()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "internal_error", "failed to list users")
		return
	}

	resp := make([]userResponse, len(users))
	for i, u := range users {
		resp[i] = toUserResponse(u)
	}

	jsonOK(w, map[string]any{
		"users": resp,
		"total": len(resp),
	})
}

type createUserRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Role        string `json:"role"`
}

func (h *userHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}

	if req.Username == "" || req.Password == "" {
		jsonError(w, http.StatusUnprocessableEntity, "validation_error", "username and password are required")
		return
	}

	// An unrecognised role is a mistake worth reporting, not one to coerce:
	// silently turning "Admin" into "user" creates an account with the wrong
	// privileges and tells the caller it worked.
	role := domain.RoleUser
	if req.Role != "" {
		parsed, ok := domain.ParseRole(req.Role)
		if !ok {
			jsonError(w, http.StatusBadRequest, "validation_error",
				`role must be "admin" or "user"`)
			return
		}
		role = parsed
	}

	claims := auth.ClaimsFromContext(r.Context())
	meta := service.AuditMeta{ActorUsername: claims.Username, IPAddress: httputil.ExtractClientIP(r, h.trustProxy)}
	user, err := h.svc.Create(req.Username, req.DisplayName, req.Password, role, meta)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrConflict):
			jsonError(w, http.StatusConflict, "username_taken", "a user with that username already exists")
		case errors.Is(err, domain.ErrUserLimitReached):
			jsonError(w, http.StatusUnprocessableEntity, "user_limit_reached", "the maximum number of users has been reached")
		case errors.Is(err, service.ErrWeakPassword):
			jsonError(w, http.StatusUnprocessableEntity, "weak_password",
				fmt.Sprintf("password must be between %d and %d bytes", auth.MinPasswordLength, auth.MaxPasswordLength))
		default:
			jsonError(w, http.StatusInternalServerError, "internal_error", "failed to create user")
		}
		return
	}

	jsonCreated(w, toUserResponse(user))
}

func (h *userHandler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		jsonError(w, http.StatusForbidden, "forbidden", "service tokens cannot access user records")
		return
	}

	// Non-admins can only access their own record
	if claims.Role != domain.RoleAdmin && claims.UserID != id {
		jsonError(w, http.StatusForbidden, "forbidden", "you can only access your own user record")
		return
	}

	user, err := h.svc.GetByID(id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			jsonError(w, http.StatusNotFound, "not_found", "user not found")
			return
		}
		jsonError(w, http.StatusInternalServerError, "internal_error", "failed to get user")
		return
	}

	jsonOK(w, toUserResponse(user))
}

type updateUserRequest struct {
	DisplayName *string `json:"display_name"`
	Password    *string `json:"password"`
	Role        *string `json:"role"`
	IsActive    *bool   `json:"is_active"`
}

func (h *userHandler) update(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "bad_request", "invalid JSON")
		return
	}

	input := service.UpdateUserInput{
		DisplayName: req.DisplayName,
		Password:    req.Password,
		IsActive:    req.IsActive,
	}
	if req.Role != nil {
		parsed, ok := domain.ParseRole(*req.Role)
		if !ok {
			jsonError(w, http.StatusBadRequest, "validation_error",
				`role must be "admin" or "user"`)
			return
		}
		input.Role = &parsed
	}

	claims := auth.ClaimsFromContext(r.Context())
	meta := service.AuditMeta{ActorUsername: claims.Username, IPAddress: httputil.ExtractClientIP(r, h.trustProxy)}
	user, err := h.svc.Update(id, input, meta)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrNotFound):
			jsonError(w, http.StatusNotFound, "not_found", "user not found")
		case errors.Is(err, domain.ErrConflict):
			jsonError(w, http.StatusConflict, "username_taken", "a user with that username already exists")
		case errors.Is(err, service.ErrWeakPassword):
			jsonError(w, http.StatusUnprocessableEntity, "weak_password",
				fmt.Sprintf("password must be between %d and %d bytes", auth.MinPasswordLength, auth.MaxPasswordLength))
		case errors.Is(err, service.ErrCannotDeleteLastAdmin):
			jsonError(w, http.StatusConflict, "cannot_delete_last_admin",
				"cannot demote or deactivate the last admin user")
		default:
			jsonError(w, http.StatusInternalServerError, "internal_error", "failed to update user")
		}
		return
	}

	jsonOK(w, toUserResponse(user))
}

func (h *userHandler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	claims := auth.ClaimsFromContext(r.Context())
	meta := service.AuditMeta{ActorUsername: claims.Username, IPAddress: httputil.ExtractClientIP(r, h.trustProxy)}
	if err := h.svc.Delete(id, meta); err != nil {
		switch {
		case errors.Is(err, domain.ErrNotFound):
			jsonError(w, http.StatusNotFound, "not_found", "user not found")
		case errors.Is(err, service.ErrCannotDeleteLastAdmin):
			jsonError(w, http.StatusConflict, "cannot_delete_last_admin", "cannot delete the last admin user")
		default:
			jsonError(w, http.StatusInternalServerError, "internal_error", "failed to delete user")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
