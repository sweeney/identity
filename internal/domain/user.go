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
