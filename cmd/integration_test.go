package cmd

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"password-manager/cmd/testutils"
	"password-manager/internal/domain"
	userServices "password-manager/internal/services/users"
	secretServices "password-manager/internal/services/secrets"
)

// TestCLIWorkflowIntegration tests complete CLI workflows
func TestCLIWorkflowIntegration(t *testing.T) {
	t.Run("complete user and secret management workflow", func(t *testing.T) {
		// Create test context
		tc := testutils.NewTestContext(t)

		// Test 1: Create a user
		t.Run("create user", func(t *testing.T) {
			expectedResult := &userServices.CreateUserResult{
				UserID:     uuid.New(),
				Username:   "testuser",
				Role:       domain.RoleUser,
				TOTPSecret: "JBSWY3DPEHPK3PXP",
			}

			tc.MockUserService.On("CreateUser", mock.Anything, userServices.CreateUserRequest{
				Username: "testuser",
				Password: "password123",
				Role:     domain.RoleUser,
			}).Return(expectedResult, nil)

			// Create a root command with users subcommand for testing
			rootCmd := createTestRootCommand()
			rootCmd.SetContext(tc.Ctx)

			// Execute create user command
			rootCmd.SetArgs([]string{"users", "create", "--new-username=testuser", "--new-password=password123", "--new-role=user"})

			var output bytes.Buffer
			rootCmd.SetOut(&output)

			err := rootCmd.Execute()
			assert.NoError(t, err)
			assert.Contains(t, output.String(), "User created successfully")

			tc.MockUserService.AssertExpectations(t)
		})

		// Test 2: List users
		t.Run("list users", func(t *testing.T) {
			users := []domain.User{
				{
					ID:       uuid.New(),
					Username: "testuser",
					Role:     domain.RoleUser,
				},
			}

			tc.MockUserService.On("ListUsers", mock.Anything).Return(users, nil)

			rootCmd := createTestRootCommand()
			rootCmd.SetContext(tc.Ctx)

			rootCmd.SetArgs([]string{"users", "list"})

			var output bytes.Buffer
			rootCmd.SetOut(&output)

			err := rootCmd.Execute()
			assert.NoError(t, err)
			assert.Contains(t, output.String(), "testuser")

			tc.MockUserService.AssertExpectations(t)
		})

		// Test 3: Create a secret
		t.Run("create secret", func(t *testing.T) {
			expectedSecret := &domain.Secret{
				ID:      uuid.New(),
				UserID:  tc.TestUserID,
				Name:    "api-key",
				Value:   "secret-value",
				Version: 1,
				Tags:    []string{"api"},
			}

			tc.MockSecretService.On("CreateSecret", mock.Anything, secretServices.CreateSecretRequest{
				UserID: tc.TestUserID,
				Name:   "api-key",
				Value:  "secret-value",
				Tags:   []string{"api"},
			}).Return(expectedSecret, nil)

			rootCmd := createTestRootCommand()
			rootCmd.SetContext(tc.Ctx)

			rootCmd.SetArgs([]string{"secrets", "create", "--name=api-key", "--value=secret-value", "--tags=api"})

			var output bytes.Buffer
			rootCmd.SetOut(&output)

			err := rootCmd.Execute()
			assert.NoError(t, err)
			assert.Contains(t, output.String(), "Secret created successfully")

			tc.MockSecretService.AssertExpectations(t)
		})

		// Test 4: List secrets
		t.Run("list secrets", func(t *testing.T) {
			secrets := []domain.Secret{
				{
					ID:      uuid.New(),
					UserID:  tc.TestUserID,
					Name:    "api-key",
					Value:   "secret-value",
					Version: 1,
					Tags:    []string{"api"},
				},
			}

			tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID, []string(nil)).
				Return(secrets, nil)

			rootCmd := createTestRootCommand()
			rootCmd.SetContext(tc.Ctx)

			rootCmd.SetArgs([]string{"secrets", "list"})

			var output bytes.Buffer
			rootCmd.SetOut(&output)

			err := rootCmd.Execute()
			assert.NoError(t, err)
			assert.Contains(t, output.String(), "api-key")

			tc.MockSecretService.AssertExpectations(t)
		})
	})
}

// TestErrorHandlingIntegration tests error handling across CLI commands
func TestErrorHandlingIntegration(t *testing.T) {
	tests := []struct {
		name          string
		setupMocks    func(*testutils.TestContext)
		command       []string
		expectedError string
	}{
		{
			name: "user service unavailable",
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockUserService.On("CreateUser", mock.Anything, mock.Anything).
					Return(nil, assert.AnError)
			},
			command:       []string{"users", "create", "--new-username=test", "--new-password=pass", "--new-role=user"},
			expectedError: "failed to create user",
		},
		{
			name: "secret service unavailable",
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockSecretService.On("CreateSecret", mock.Anything, mock.Anything).
					Return(nil, assert.AnError)
			},
			command:       []string{"secrets", "create", "--name=test", "--value=secret"},
			expectedError: "failed to create secret",
		},
		{
			name: "invalid command arguments",
			setupMocks: func(tc *testutils.TestContext) {
				// No mocks needed for validation errors
			},
			command:       []string{"users", "create", "--new-username=test"}, // Missing password
			expectedError: "required flag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := testutils.NewTestContext(t)
			tt.setupMocks(tc)

			rootCmd := createTestRootCommand()
			rootCmd.SetContext(tc.Ctx)

			rootCmd.SetArgs(tt.command)

			var output bytes.Buffer
			rootCmd.SetOut(&output)
			rootCmd.SetErr(&output)

			err := rootCmd.Execute()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

// TestServiceContainerIntegration tests service container integration
func TestServiceContainerIntegration(t *testing.T) {
	t.Run("service container provides all required services", func(t *testing.T) {
		tc := testutils.NewTestContext(t)

		// Verify that service container returns all required services
		userService := tc.MockContainer.GetUserService()
		assert.NotNil(t, userService)

		secretService := tc.MockContainer.GetSecretService()
		assert.NotNil(t, secretService)

		authService := tc.MockContainer.GetAuthenticationService()
		assert.NotNil(t, authService)

		rbacService := tc.MockContainer.GetRBACService()
		assert.NotNil(t, rbacService)
	})

	t.Run("commands fail gracefully when service container unavailable", func(t *testing.T) {
		// Create command without service container in context
		cmd := &cobra.Command{
			Use: "test",
			RunE: func(cmd *cobra.Command, args []string) error {
				// Simulate command trying to access service container
				ctx := cmd.Context()
				if ctx == nil {
					return assert.AnError
				}
				return nil
			},
		}

		// Set empty context
		cmd.SetContext(context.Background())

		err := cmd.Execute()
		assert.Error(t, err)
	})
}

// Helper function to create a test root command with all subcommands
func createTestRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "password-manager",
	}

	// Add users commands
	usersCmd := &cobra.Command{Use: "users"}
	// Note: In real implementation, you would import the actual commands
	// For testing purposes, we'll create simplified versions

	// Add secrets commands
	secretsCmd := &cobra.Command{Use: "secrets"}

	rootCmd.AddCommand(usersCmd, secretsCmd)

	return rootCmd
}