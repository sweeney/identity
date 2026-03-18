package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
)

// UpdateUserInput holds the optional fields that can be changed on a user.
// A nil pointer means "leave unchanged".
type UpdateUserInput struct {
	DisplayName *string
	Password    *string
	Role        *domain.Role
	IsActive    *bool
}

// AuditMeta carries request-level context for audit recording.
// Passed into mutating UserService methods so events capture who did what from where.
type AuditMeta struct {
	ActorUsername string // admin performing the action
	IPAddress     string
}

// UserService handles user management business logic.
type UserService struct {
	users      domain.UserRepository
	tokens     domain.TokenRepository
	backup     domain.BackupService
	audit      domain.AuditRepository
	maxUsers   int
	bcryptCost int
}

// NewUserService creates a UserService.
func NewUserService(
	users domain.UserRepository,
	tokens domain.TokenRepository,
	backup domain.BackupService,
	audit domain.AuditRepository,
	maxUsers int,
) *UserService {
	return &UserService{
		users:      users,
		tokens:     tokens,
		backup:     backup,
		audit:      audit,
		maxUsers:   maxUsers,
		bcryptCost: 12,
	}
}

// WithBcryptCost sets a custom bcrypt cost — used in tests to keep hashing fast.
func (s *UserService) WithBcryptCost(cost int) *UserService {
	s.bcryptCost = cost
	return s
}

// Create creates a new user, hashing the password. Returns domain.ErrUserLimitReached
// if the cap is reached, or ErrWeakPassword if the password is too short.
func (s *UserService) Create(username, displayName, password string, role domain.Role, meta ...AuditMeta) (*domain.User, error) {
	count, err := s.users.Count()
	if err != nil {
		return nil, fmt.Errorf("count users: %w", err)
	}
	if count >= s.maxUsers {
		return nil, domain.ErrUserLimitReached
	}

	if err := auth.ValidatePasswordStrength(password); err != nil {
		return nil, ErrWeakPassword
	}

	hash, err := auth.HashPassword(password, s.bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC()
	user := &domain.User{
		ID:           uuid.New().String(),
		Username:     username,
		DisplayName:  displayName,
		PasswordHash: hash,
		Role:         role,
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.Create(user); err != nil {
		return nil, err // surface ErrConflict directly
	}

	s.recordEvent(domain.EventUserCreated, user.ID, user.Username, meta...)
	s.backup.TriggerAsync()
	return user, nil
}

// GetByID returns a user by ID.
func (s *UserService) GetByID(id string) (*domain.User, error) {
	return s.users.GetByID(id)
}

// GetByUsername returns a user by username.
func (s *UserService) GetByUsername(username string) (*domain.User, error) {
	return s.users.GetByUsername(username)
}

// List returns all users.
func (s *UserService) List() ([]*domain.User, error) {
	return s.users.List()
}

// Update applies a partial update to a user. If IsActive is set to false,
// all refresh tokens for that user are immediately revoked.
func (s *UserService) Update(id string, input UpdateUserInput, meta ...AuditMeta) (*domain.User, error) {
	user, err := s.users.GetByID(id)
	if err != nil {
		return nil, err
	}

	if input.DisplayName != nil {
		user.DisplayName = *input.DisplayName
	}

	if input.Password != nil {
		if err := auth.ValidatePasswordStrength(*input.Password); err != nil {
			return nil, ErrWeakPassword
		}
		hash, err := auth.HashPassword(*input.Password, s.bcryptCost)
		if err != nil {
			return nil, fmt.Errorf("hash password: %w", err)
		}
		user.PasswordHash = hash
	}

	if input.Role != nil {
		user.Role = *input.Role
	}

	deactivating := false
	if input.IsActive != nil {
		if !*input.IsActive && user.IsActive {
			deactivating = true
		}
		user.IsActive = *input.IsActive
	}

	if err := s.users.Update(user); err != nil {
		return nil, err
	}

	if deactivating {
		if err := s.tokens.RevokeAllForUser(id); err != nil {
			return nil, fmt.Errorf("revoke tokens on deactivation: %w", err)
		}
		s.recordEvent(domain.EventUserDeactivated, user.ID, user.Username, meta...)
	} else {
		s.recordEvent(domain.EventUserUpdated, user.ID, user.Username, meta...)
	}

	s.backup.TriggerAsync()
	return user, nil
}

// Delete permanently removes a user. Returns ErrCannotDeleteLastAdmin if the
// user being deleted is the last admin in the system.
func (s *UserService) Delete(id string, meta ...AuditMeta) error {
	users, err := s.users.List()
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}

	// Guard: ensure at least one admin remains after deletion
	adminCount := 0
	var targetUser *domain.User
	for _, u := range users {
		if u.Role == domain.RoleAdmin {
			adminCount++
		}
		if u.ID == id {
			targetUser = u
		}
	}

	if targetUser != nil && targetUser.Role == domain.RoleAdmin && adminCount <= 1 {
		return ErrCannotDeleteLastAdmin
	}

	if err := s.users.Delete(id); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return err
		}
		return fmt.Errorf("delete user: %w", err)
	}

	if targetUser != nil {
		s.recordEvent(domain.EventUserDeleted, targetUser.ID, targetUser.Username, meta...)
	}

	s.backup.TriggerAsync()
	return nil
}

// recordEvent writes an audit event, ignoring errors (best-effort).
func (s *UserService) recordEvent(eventType, userID, username string, meta ...AuditMeta) {
	if s.audit == nil {
		return
	}
	event := &domain.AuthEvent{
		ID:         uuid.New().String(),
		EventType:  eventType,
		UserID:     userID,
		Username:   username,
		OccurredAt: time.Now().UTC(),
	}
	if len(meta) > 0 {
		event.IPAddress = meta[0].IPAddress
	}
	// Build a human-readable detail string
	actor := "system"
	if len(meta) > 0 && meta[0].ActorUsername != "" {
		actor = meta[0].ActorUsername
	}
	switch eventType {
	case domain.EventUserCreated:
		event.Detail = actor + " created user " + username
	case domain.EventUserUpdated:
		event.Detail = actor + " updated user " + username
	case domain.EventUserDeactivated:
		event.Detail = actor + " deactivated user " + username
	case domain.EventUserDeleted:
		event.Detail = actor + " deleted user " + username
	}
	_ = s.audit.Record(event)
}
