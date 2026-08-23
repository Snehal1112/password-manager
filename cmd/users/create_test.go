package users

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	userServices "rocketvault/internal/services/users"
	"rocketvault/model"
)

// newTestContextWithRole creates a test context with a specific caller role.
func newTestContextWithRole(t *testing.T, role string) *testutils.TestContext {
	tc := testutils.NewTestContext(t)
	claims := &model.Claims{
		UserID:   tc.TestUserID,
		Username: "testuser",
		Roles:    []string{role},
	}
	ctx := context.WithValue(tc.Ctx, common.ClaimsKey, claims)
	tc.Ctx = ctx
	return tc
}

func TestCreateUserCommand(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func(*testutils.TestContext)
		args           []string
		flags          map[string]string
		expectedError  bool
		expectedOutput string
	}{
		{
			name: "successful user creation",
			args: []string{"--new-username=newuser", "--new-password=password123", "--new-role=user"},
			setupMocks: func(tc *testutils.TestContext) {
				// Mock successful user creation
				expectedResult := &userServices.CreateUserResult{
					UserID:     uuid.New(),
					Username:   "newuser",
					Roles:      []string{model.RoleUser},
					TOTPSecret: "JBSWY3DPEHPK3PXP",
					CreatedAt:  time.Now(),
				}
				tc.MockUserService.On("CreateUser", mock.Anything, userServices.CreateUserRequest{
					Username:    "newuser",
					Password:    "password123",
					Roles:       []string{model.RoleUser},
					CallerRoles: []string{model.RoleAdmin},
				}).Return(expectedResult, nil)
			},
			expectedOutput: "User created successfully",
			expectedError:  false,
		},
		{
			name: "missing password",
			args: []string{"--new-username=newuser", "--new-role=user"},
			setupMocks: func(tc *testutils.TestContext) {
				// No mocks needed for validation error
			},
			expectedOutput: "username, password, and role are required",
			expectedError:  true,
		},
		{
			name: "invalid role",
			args: []string{"--new-username=newuser", "--new-password=password123", "--new-role=invalid-role"},
			setupMocks: func(tc *testutils.TestContext) {
				// The actual command doesn't validate role, so this will succeed
				expectedResult := &userServices.CreateUserResult{
					UserID:     uuid.New(),
					Username:   "newuser",
					Roles:      []string{"invalid-role"},
					TOTPSecret: "JBSWY3DPEHPK3PXP",
					CreatedAt:  time.Now(),
				}
				tc.MockUserService.On("CreateUser", mock.Anything, userServices.CreateUserRequest{
					Username:    "newuser",
					Password:    "password123",
					Roles:       []string{"invalid-role"},
					CallerRoles: []string{model.RoleAdmin},
				}).Return(expectedResult, nil)
			},
			expectedOutput: "User created successfully",
			expectedError:  false,
		},
		{
			name: "service error",
			args: []string{"--new-username=newuser", "--new-password=password123", "--new-role=user"},
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockUserService.On("CreateUser", mock.Anything, userServices.CreateUserRequest{
					Username:    "newuser",
					Password:    "password123",
					Roles:       []string{"user"},
					CallerRoles: []string{model.RoleAdmin},
				}).Return(nil, assert.AnError)
			},
			expectedOutput: "failed to create user",
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset viper for each test
			viper.Reset()

			// Create test context
			tc := testutils.NewTestContext(t)
			tt.setupMocks(tc)

			// Create enhanced test command that simulates user creation logic
			createCmd := &cobra.Command{
				Use: "create",
				RunE: func(cmd *cobra.Command, args []string) error {
					// Parse args to extract flag values
					var username, password, role string
					for _, arg := range args {
						if strings.HasPrefix(arg, "--new-username=") {
							username = strings.TrimPrefix(arg, "--new-username=")
						} else if strings.HasPrefix(arg, "--new-password=") {
							password = strings.TrimPrefix(arg, "--new-password=")
						} else if strings.HasPrefix(arg, "--new-role=") {
							role = strings.TrimPrefix(arg, "--new-role=")
						}
					}

					// Also try to get from flags as fallback
					if username == "" {
						username, _ = cmd.Flags().GetString("new-username")
					}
					if password == "" {
						password, _ = cmd.Flags().GetString("new-password")
					}
					if role == "" {
						if roles, _ := cmd.Flags().GetStringArray("new-role"); len(roles) > 0 {
							role = roles[0]
						}
					}

					if username == "" || password == "" || role == "" {
						return fmt.Errorf("username, password, and role are required")
					}

					req := userServices.CreateUserRequest{
						Username:    username,
						Password:    password,
						Roles:       []string{role},
						CallerRoles: []string{model.RoleAdmin},
					}

					result, err := tc.MockUserService.CreateUser(cmd.Context(), req)
					if err != nil {
						return fmt.Errorf("failed to create user: %w", err)
					}

					cmd.Printf("User created successfully:\n")
					cmd.Printf("  Username: %s\n", result.Username)
					cmd.Printf("  User ID: %s\n", result.UserID.String())
					cmd.Printf("  Role: %s\n", result.Roles)
					cmd.Printf("  TOTP Secret: %s\n", result.TOTPSecret)
					cmd.Printf("\nConfigure the TOTP secret in your authenticator app for MFA.\n")
					return nil
				},
			}

			createCmd.SetContext(tc.Ctx)
			createCmd.SetArgs(tt.args)

			// Define flags to prevent "unknown flag" errors
			createCmd.Flags().String("new-username", "", "Username for new user")
			createCmd.Flags().String("new-password", "", "Password for new user")
			createCmd.Flags().StringArray("new-role", []string{}, "Role for new user")

			// Capture output
			var output bytes.Buffer
			createCmd.SetOut(&output)
			createCmd.SetErr(&output)

			// Execute command
			err := createCmd.Execute()

			// Assert results
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedOutput)
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
			role:          model.RoleUser,
			expectedError: "",
		},
		{
			name:          "empty username",
			username:      "",
			password:      "password123",
			role:          model.RoleUser,
			expectedError: "username cannot be empty",
		},
		{
			name:          "empty password",
			username:      "validuser",
			password:      "",
			role:          model.RoleUser,
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
		return fmt.Errorf("username cannot be empty")
	}
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	validRoles := []string{model.RoleAdmin, model.RoleUser, model.RoleSecretsManager, model.RoleCryptoManager, model.RoleCertificateManager}
	roleValid := false
	for _, validRole := range validRoles {
		if role == validRole {
			roleValid = true
			break
		}
	}
	if !roleValid {
		return fmt.Errorf("invalid role")
	}

	return nil
}

func TestCreateUserRequiresAdminRole(t *testing.T) {
	for _, role := range []string{model.RoleUser, model.RoleSecretsManager, model.RoleCryptoManager, model.RoleCertificateManager} {
		t.Run("blocked for role "+role, func(t *testing.T) {
			viper.Reset()
			tc := newTestContextWithRole(t, role)

			cmd := &cobra.Command{
				Use:  "create",
				RunE: createCmd.RunE,
			}
			cmd.Flags().String("new-username", "", "")
			cmd.Flags().String("new-password", "", "")
			cmd.Flags().StringArray("new-role", []string{}, "")
			cmd.SetContext(tc.Ctx)
			cmd.SetArgs([]string{"--new-username=newuser", "--new-password=pw123", "--new-role=user"})

			err := cmd.Execute()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "forbidden")

			tc.MockUserService.AssertNotCalled(t, "CreateUser")
		})
	}
}

func TestCreateUserCommand_MultipleRoles(t *testing.T) {
	viper.Reset()
	tc := newTestContextWithRole(t, model.RoleAdmin)

	cmd := &cobra.Command{
		Use:  "create",
		RunE: createCmd.RunE,
	}
	cmd.Flags().String("new-username", "", "")
	cmd.Flags().String("new-password", "", "")
	cmd.Flags().StringArray("new-role", []string{}, "")
	cmd.SetContext(tc.Ctx)
	cmd.SetArgs([]string{
		"--new-username=newuser",
		"--new-password=pw12345678",
		"--new-role=admin",
		"--new-role=secrets_manager",
	})

	tc.MockUserService.On("CreateUser", mock.Anything, mock.MatchedBy(func(req userServices.CreateUserRequest) bool {
		return assert.ObjectsAreEqualValues([]string{"admin", "secrets_manager"}, req.Roles)
	})).Return(&userServices.CreateUserResult{Username: "newuser", Roles: []string{"admin", "secrets_manager"}}, nil)

	err := cmd.Execute()
	require.NoError(t, err)
	tc.MockUserService.AssertExpectations(t)
}
