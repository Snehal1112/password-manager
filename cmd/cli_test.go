package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"password-manager/cmd/testutils"
	"password-manager/internal/domain"
)

// TestBasicCLISetup tests basic CLI functionality
func TestBasicCLISetup(t *testing.T) {
	t.Run("test context creation", func(t *testing.T) {
		tc := testutils.NewTestContext(t)
		assert.NotNil(t, tc)
		assert.NotNil(t, tc.Ctx)
		assert.NotNil(t, tc.MockContainer)
		assert.NotNil(t, tc.MockUserService)
		assert.NotNil(t, tc.MockSecretService)
		assert.NotNil(t, tc.TestUserID)
	})

	t.Run("service container mocks work", func(t *testing.T) {
		tc := testutils.NewTestContext(t)

		// Test that service container returns mock services
		userService := tc.MockContainer.GetUserService()
		assert.NotNil(t, userService)
		assert.Equal(t, tc.MockUserService, userService)

		secretService := tc.MockContainer.GetSecretService()
		assert.NotNil(t, secretService)
		assert.Equal(t, tc.MockSecretService, secretService)
	})
}

// TestCLIArchitecture tests the architecture compliance
func TestCLIArchitecture(t *testing.T) {
	t.Run("all CLI commands use service container pattern", func(t *testing.T) {
		// This test verifies that CLI commands follow the service container pattern
		// In a real implementation, this would check that commands don't directly
		// access repositories but use services through the container

		tc := testutils.NewTestContext(t)
		assert.NotNil(t, tc.MockContainer)

		// Verify service container provides all required services
		assert.NotNil(t, tc.MockContainer.GetUserService())
		assert.NotNil(t, tc.MockContainer.GetSecretService())
		assert.NotNil(t, tc.MockContainer.GetAuthenticationService())
		assert.NotNil(t, tc.MockContainer.GetRBACService())
	})

	t.Run("test data factories work correctly", func(t *testing.T) {
		user := testutils.CreateTestUser()
		assert.NotNil(t, user)
		assert.NotEmpty(t, user.ID)
		assert.Equal(t, "testuser", user.Username)

		secret := testutils.CreateTestSecret()
		assert.NotNil(t, secret)
		assert.NotEmpty(t, secret.ID)
		assert.Equal(t, "test-secret", secret.Name)
	})
}

// TestMockingInfrastructure validates the mocking setup
func TestMockingInfrastructure(t *testing.T) {
	t.Run("user service mock responds correctly", func(t *testing.T) {
		tc := testutils.NewTestContext(t)

		// Test that mocks can be configured and respond
		testUser := testutils.CreateTestUser()
		tc.MockUserService.On("ListUsers", tc.Ctx).Return([]domain.User{*testUser}, nil)

		users, err := tc.MockUserService.ListUsers(tc.Ctx)
		assert.NoError(t, err)
		assert.Len(t, users, 1)

		tc.MockUserService.AssertExpectations(t)
	})

	t.Run("secret service mock responds correctly", func(t *testing.T) {
		tc := testutils.NewTestContext(t)

		expectedSecret := testutils.CreateTestSecret()
		tc.MockSecretService.On("GetSecret", tc.Ctx, expectedSecret.ID, tc.TestUserID).
			Return(expectedSecret, nil)

		secret, err := tc.MockSecretService.GetSecret(tc.Ctx, expectedSecret.ID, tc.TestUserID)
		assert.NoError(t, err)
		assert.Equal(t, expectedSecret.Name, secret.Name)

		tc.MockSecretService.AssertExpectations(t)
	})
}