package service_test

// last_admin_test.go covers WP2 (GHSA-4p62-wv6w-4vqf): UserService.Delete
// guards the last admin, and Update did not.
//
// One defect, two ways to trigger it. Demoting the only admin to `user`, or
// deactivating them, permanently locks the admin plane: nobody can reach
// /admin/, nobody can promote anyone back, and the recovery is shell access on
// the host to run --reset-admin. No caller compensated — the API and the admin
// UI both went straight through to Update.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

func soleAdmin() *domain.User {
	return &domain.User{ID: "admin-only", Username: "root", Role: domain.RoleAdmin, IsActive: true}
}

func TestUserService_Update_LastAdmin(t *testing.T) {
	roleUser := domain.RoleUser
	roleAdmin := domain.RoleAdmin
	inactive := false
	active := true
	name := "Renamed"

	tests := []struct {
		name    string
		input   service.UpdateUserInput
		wantErr bool
	}{
		{
			name:    "demoting the last admin is refused",
			input:   service.UpdateUserInput{Role: &roleUser},
			wantErr: true,
		},
		{
			name:    "deactivating the last admin is refused",
			input:   service.UpdateUserInput{IsActive: &inactive},
			wantErr: true,
		},
		{
			name:    "demoting and deactivating at once is refused",
			input:   service.UpdateUserInput{Role: &roleUser, IsActive: &inactive},
			wantErr: true,
		},
		{
			name:  "an unrelated edit to the last admin is allowed",
			input: service.UpdateUserInput{DisplayName: &name},
		},
		{
			name:  "re-affirming the last admin's role and status is allowed",
			input: service.UpdateUserInput{Role: &roleAdmin, IsActive: &active},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			userRepo := mocks.NewMockUserRepository(ctrl)
			tokenRepo := mocks.NewMockTokenRepository(ctrl)
			backupSvc := mocks.NewMockBackupService(ctrl)

			userRepo.EXPECT().GetByID("admin-only").Return(soleAdmin(), nil).AnyTimes()
			userRepo.EXPECT().List().Return([]*domain.User{soleAdmin()}, nil).AnyTimes()
			if !tc.wantErr {
				userRepo.EXPECT().Update(gomock.Any()).Return(nil)
				backupSvc.EXPECT().TriggerAsync().AnyTimes()
			}

			svc := service.NewUserService(userRepo, tokenRepo, backupSvc, nil, maxUsers).WithBcryptCost(4)
			_, err := svc.Update("admin-only", tc.input)

			if tc.wantErr {
				require.Error(t, err, "the last admin must not be demotable or deactivatable")
				assert.ErrorIs(t, err, service.ErrCannotDeleteLastAdmin)
				return
			}
			require.NoError(t, err)
		})
	}
}

// With a second admin present, both operations are ordinary edits.
func TestUserService_Update_NotLastAdmin_Allowed(t *testing.T) {
	roleUser := domain.RoleUser
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	userRepo.EXPECT().GetByID("admin-1").Return(
		&domain.User{ID: "admin-1", Username: "root", Role: domain.RoleAdmin, IsActive: true}, nil).AnyTimes()
	userRepo.EXPECT().List().Return([]*domain.User{
		{ID: "admin-1", Role: domain.RoleAdmin, IsActive: true},
		{ID: "admin-2", Role: domain.RoleAdmin, IsActive: true},
	}, nil).AnyTimes()
	userRepo.EXPECT().Update(gomock.Any()).Return(nil)
	backupSvc.EXPECT().TriggerAsync().AnyTimes()

	svc := service.NewUserService(userRepo, tokenRepo, backupSvc, nil, maxUsers).WithBcryptCost(4)
	_, err := svc.Update("admin-1", service.UpdateUserInput{Role: &roleUser})
	require.NoError(t, err)
}
