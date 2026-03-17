package service_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

const maxUsers = 10

func TestUserService_Create_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	userRepo.EXPECT().Count().Return(2, nil)
	userRepo.EXPECT().Create(gomock.Any()).Return(nil)
	backupSvc.EXPECT().TriggerAsync()

	svc := service.NewUserService(userRepo, tokenRepo, backupSvc, nil, maxUsers).WithBcryptCost(4)

	user, err := svc.Create("newuser", "New User", "goodpassword1234", domain.RoleUser)
	require.NoError(t, err)
	assert.NotEmpty(t, user.ID)
	assert.Equal(t, "newuser", user.Username)
	assert.Equal(t, domain.RoleUser, user.Role)
	assert.True(t, user.IsActive)
	// Password should be hashed, not stored in plain text
	assert.NotEqual(t, "goodpassword1234", user.PasswordHash)
}

func TestUserService_Create_UserLimitReached(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	userRepo.EXPECT().Count().Return(maxUsers, nil)

	svc := service.NewUserService(userRepo, tokenRepo, backupSvc, nil, maxUsers).WithBcryptCost(4)

	_, err := svc.Create("overflow", "Overflow", "goodpassword1234", domain.RoleUser)
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrUserLimitReached)
}

func TestUserService_Create_WeakPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	userRepo.EXPECT().Count().Return(1, nil)

	svc := service.NewUserService(userRepo, tokenRepo, backupSvc, nil, maxUsers).WithBcryptCost(4)

	_, err := svc.Create("user", "User", "short", domain.RoleUser)
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrWeakPassword)
}

func TestUserService_Create_DuplicateUsername(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	userRepo.EXPECT().Count().Return(1, nil)
	userRepo.EXPECT().Create(gomock.Any()).Return(domain.ErrConflict)

	svc := service.NewUserService(userRepo, tokenRepo, backupSvc, nil, maxUsers).WithBcryptCost(4)

	_, err := svc.Create("existinguser", "Display", "goodpassword1234", domain.RoleUser)
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrConflict)
}

func TestUserService_Update_ChangeDisplayName(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	existing := activeUser()
	userRepo.EXPECT().GetByID("user-123").Return(existing, nil)
	userRepo.EXPECT().Update(gomock.Any()).Return(nil)
	backupSvc.EXPECT().TriggerAsync()

	svc := service.NewUserService(userRepo, tokenRepo, backupSvc, nil, maxUsers)

	updated, err := svc.Update("user-123", service.UpdateUserInput{DisplayName: ptr("New Name")})
	require.NoError(t, err)
	assert.Equal(t, "New Name", updated.DisplayName)
}

func TestUserService_Update_ChangePassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	existing := activeUser()
	userRepo.EXPECT().GetByID("user-123").Return(existing, nil)
	userRepo.EXPECT().Update(gomock.Any()).DoAndReturn(func(u *domain.User) error {
		// Verify password was changed and re-hashed
		assert.NoError(t, auth.CheckPassword("newpassword1234", u.PasswordHash))
		return nil
	})
	backupSvc.EXPECT().TriggerAsync()

	svc := service.NewUserService(userRepo, tokenRepo, backupSvc, nil, maxUsers).WithBcryptCost(4)

	_, err := svc.Update("user-123", service.UpdateUserInput{Password: ptr("newpassword1234")})
	require.NoError(t, err)
}

func TestUserService_Update_WeakPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	existing := activeUser()
	userRepo.EXPECT().GetByID("user-123").Return(existing, nil)

	svc := service.NewUserService(userRepo, tokenRepo, backupSvc, nil, maxUsers).WithBcryptCost(4)

	_, err := svc.Update("user-123", service.UpdateUserInput{Password: ptr("short")})
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrWeakPassword)
}

func TestUserService_Update_DeactivateRevokesTokens(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	existing := activeUser()
	userRepo.EXPECT().GetByID("user-123").Return(existing, nil)
	userRepo.EXPECT().Update(gomock.Any()).Return(nil)
	// Deactivating must revoke all tokens
	tokenRepo.EXPECT().RevokeAllForUser("user-123").Return(nil)
	backupSvc.EXPECT().TriggerAsync()

	svc := service.NewUserService(userRepo, tokenRepo, backupSvc, nil, maxUsers)

	isActive := false
	_, err := svc.Update("user-123", service.UpdateUserInput{IsActive: &isActive})
	require.NoError(t, err)
}

func TestUserService_Delete_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	// Simulate there being two admins so deletion is allowed
	userRepo.EXPECT().List().Return([]*domain.User{
		{ID: "user-123", Role: domain.RoleUser},
		{ID: "admin-1", Role: domain.RoleAdmin},
	}, nil)
	userRepo.EXPECT().Delete("user-123").Return(nil)
	backupSvc.EXPECT().TriggerAsync()

	svc := service.NewUserService(userRepo, tokenRepo, backupSvc, nil, maxUsers).WithBcryptCost(4)

	err := svc.Delete("user-123")
	require.NoError(t, err)
}

func TestUserService_Delete_LastAdmin(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	// Only one admin exists
	userRepo.EXPECT().List().Return([]*domain.User{
		{ID: "admin-only", Role: domain.RoleAdmin},
	}, nil)

	svc := service.NewUserService(userRepo, tokenRepo, backupSvc, nil, maxUsers).WithBcryptCost(4)

	err := svc.Delete("admin-only")
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrCannotDeleteLastAdmin)
}

func ptr[T any](v T) *T { return &v }
