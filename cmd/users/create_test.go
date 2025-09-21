package users

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"password-manager/cmd/testutils"
	"password-manager/internal/domain"
	userServices "password-manager/internal/services/users"
)

func TestCreateUserCommand(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func(*testutils.TestContext)
		args           []string
		flags          map[string]string
		expectedError  string
		expectedOutput string
	}{
		{
			name: "successful user creation",
			setupMocks: func(tc *testutils.TestContext) {
				// Mock successful user creation
				expectedResult := &userServices.CreateUserResult{
					UserID:     uuid.New(),
					Username:   "newuser",
					Role:       domain.RoleUser,
					TOTPSecret: "JBSWY3DPEHPK3PXP",
					CreatedAt:  time.Now(),
				}
				tc.MockUserService.On("CreateUser", mock.Anything, userServices.CreateUserRequest{
					Username: "newuser",
					Password: "password123",
					Role:     domain.RoleUser,
				}).Return(expectedResult, nil)
			},
			flags: map[string]string{
				"new-username": "newuser",
				"new-password": "password123",
				"new-role":     "user",
			},
			expectedOutput: "✅ User created successfully",
		},
		{
			name: "missing required flag",
			setupMocks: func(tc *testutils.TestContext) {
				// No mocks needed for validation error
			},
			flags: map[string]string{
				"new-username": "newuser",
				// Missing new-password
			},
			expectedError: "new password is required",
		},
		{
			name: "invalid role",
			setupMocks: func(tc *testutils.TestContext) {
				// No mocks needed for validation error
			},
			flags: map[string]string{
				"new-username": "newuser",
				"new-password": "password123",
				"new-role":     "invalid-role",
			},
			expectedError: "invalid role",
		},
		{
			name: "service error",
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockUserService.On("CreateUser", mock.Anything, mock.Anything).
					Return(nil, assert.AnError)
			},
			flags: map[string]string{
				"new-username": "newuser",
				"new-password": "password123",
				"new-role":     "user",
			},
			expectedError: "failed to create user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper for each test
			viper.Reset()

			// Create test context
			tc := testutils.NewTestContext(t)
			tt.setupMocks(tc)

			// Create command with test context
			testCmd := tc.CreateTestCommand(createCmd)

			// Set up flags
			for flag, value := range tt.flags {
				err := testCmd.Flags().Set(flag, value)
				assert.NoError(t, err)
			}

			// Capture output
			var output bytes.Buffer
			testCmd.SetOut(&output)
			testCmd.SetErr(&output)

			// Execute command
			err := testCmd.Execute()

			// Assert results
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				if tt.expectedOutput != "" {
					assert.Contains(t, output.String(), tt.expectedOutput)
				}
			}

			// Verify mock expectations
			tc.MockUserService.AssertExpectations(t)
		})
	}
}

func TestCreateUserValidation(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		password      string
		role          string
		expectedError string
	}{
		{
			name:          "valid input",
			username:      "validuser",
			password:      "password123",
			role:          domain.RoleUser,
			expectedError: "",
		},
		{
			name:          "empty username",
			username:      "",
			password:      "password123",
			role:          domain.RoleUser,
			expectedError: "username cannot be empty",
		},
		{
			name:          "empty password",
			username:      "validuser",
			password:      "",
			role:          domain.RoleUser,
			expectedError: "password cannot be empty",
		},
		{
			name:          "invalid role",
			username:      "validuser",
			password:      "password123",
			role:          "invalid",
			expectedError: "invalid role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCreateUserInput(tt.username, tt.password, tt.role)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper function to validate user creation input
func validateCreateUserInput(username, password, role string) error {
	if username == "" {
		return assert.AnError // Replace with actual validation
	}
	if password == "" {
		return assert.AnError // Replace with actual validation
	}

	validRoles := []string{domain.RoleAdmin, domain.RoleUser, domain.RoleSecretsManager, domain.RoleCryptoManager, domain.RoleCertificateManager}
	roleValid := false
	for _, validRole := range validRoles {
		if role == validRole {
			roleValid = true
			break
		}
	}
	if !roleValid {
		return assert.AnError // Replace with actual validation
	}

	return nil
}

// Test helper to create a root command for testing
func createTestRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "password-manager",
	}

	usersCmd := &cobra.Command{
		Use: "users",
	}

	usersCmd.AddCommand(createCmd)
	rootCmd.AddCommand(usersCmd)

	return rootCmd
}
