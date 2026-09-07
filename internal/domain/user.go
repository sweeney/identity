package domain

import (
	"time"

	commonauth "github.com/sweeney/identity/common/auth"
)

// Role is an alias for the common auth Role type.
type Role = commonauth.Role

const (
	RoleAdmin = commonauth.RoleAdmin
	RoleUser  = commonauth.RoleUser
)

// User is the core user entity.
type User struct {
	ID           string
	Username     string
	DisplayName  string
	PasswordHash string
	Role         Role
	IsActive     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserRepository defines all persistence operations for users.
// ParseRole converts a string to a Role, rejecting anything that is not one of
// the two the system understands.
//
// Silently coercing an unrecognised value is worse than refusing it: coercing
// to "user" turns a typo into an account with the wrong privileges and reports
// success, and storing the string verbatim produces a role that is neither —
// RequireAdmin compares against "admin", so "Admin" is not an admin, and it is
// not a plain user either.
func ParseRole(s string) (Role, bool) {
	switch Role(s) {
	case RoleAdmin:
		return RoleAdmin, true
	case RoleUser:
		return RoleUser, true
	default:
		return "", false
	}
}

//
//go:generate mockgen -destination=../mocks/mock_user_repository.go -package=mocks github.com/sweeney/identity/internal/domain UserRepository
type UserRepository interface {
	Create(user *User) error
	GetByID(id string) (*User, error)
	GetByUsername(username string) (*User, error)
	Update(user *User) error
	Delete(id string) error
	List() ([]*User, error)
	Count() (int, error)
}
