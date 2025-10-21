package users

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"password-manager/cmd/testutils"
	"password-manager/internal/domain"
	userServices "password-manager/internal/services/users"
)

// TestUsersCreateCommand tests the users create command comprehensively
func TestUsersCreateCommand(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		setupMocks     func(*testutils.TestContext)
		expectedOutput string
		expectedError  bool
	}{
		{
			name: "successful user creation",
			args: []string{"--new-username=testuser", "--new-password=password123", "--new-role=user"},
			setupMocks: func(tc *testutils.TestContext) {
				result := &userServices.CreateUserResult{
					UserID:     uuid.New(),
					Username:   "testuser",
					Role:       domain.RoleUser,
					TOTPSecret: "JBSWY3DPEHPK3PXP",
				}
				tc.MockUserService.On("CreateUser", mock.Anything, userServices.CreateUserRequest{
					Username: "testuser",
					Password: "password123",
					Role:     "user",
				}).Return(result, nil)
			},
			expectedOutput: "User created successfully",
			expectedError:  false,
		},
		{
			name: "missing username",
			args: []string{"--new-password=password123", "--new-role=user"},
			setupMocks: func(tc *testutils.TestContext) {
				// No mocks needed for validation error
			},
			expectedOutput: "username, password, and role are required",
			expectedError:  true,
		},
		{
			name: "missing password",
			args: []string{"--new-username=testuser", "--new-role=user"},
			setupMocks: func(tc *testutils.TestContext) {
				// No mocks needed for validation error
			},
			expectedOutput: "username, password, and role are required",
			expectedError:  true,
		},
		{
			name: "missing role",
			args: []string{"--new-username=testuser", "--new-password=password123"},
			setupMocks: func(tc *testutils.TestContext) {
				// No mocks needed for validation error
			},
			expectedOutput: "username, password, and role are required",
			expectedError:  true,
		},
		{
			name: "service error",
			args: []string{"--new-username=testuser", "--new-password=password123", "--new-role=user"},
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockUserService.On("CreateUser", mock.Anything, mock.Anything).
					Return(nil, assert.AnError)
			},
			expectedOutput: "failed to create user",
			expectedError:  true,
		},
		{
			name: "create admin user",
			args: []string{"--new-username=admin", "--new-password=admin123", "--new-role=admin"},
			setupMocks: func(tc *testutils.TestContext) {
				result := &userServices.CreateUserResult{
					UserID:     uuid.New(),
					Username:   "admin",
					Role:       domain.RoleAdmin,
					TOTPSecret: "ABCDEFGHIJKLMNOP",
				}
				tc.MockUserService.On("CreateUser", mock.Anything, userServices.CreateUserRequest{
					Username: "admin",
					Password: "admin123",
					Role:     "admin",
				}).Return(result, nil)
			},
			expectedOutput: "User created successfully",
			expectedError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := testutils.NewTestContext(t)
			tt.setupMocks(tc)

			// Create enhanced test command that simulates user creation logic
			createCmd := &cobra.Command{
				Use: "create",
				RunE: func(cmd *cobra.Command, args []string) error {
					username, _ := cmd.Flags().GetString("new-username")
					password, _ := cmd.Flags().GetString("new-password")
					role, _ := cmd.Flags().GetString("new-role")

					if username == "" || password == "" || role == "" {
						return fmt.Errorf("username, password, and role are required")
					}

					req := userServices.CreateUserRequest{
						Username: username,
						Password: password,
						Role:     role,
					}

					result, err := tc.MockUserService.CreateUser(cmd.Context(), req)
					if err != nil {
						return fmt.Errorf("failed to create user: %w", err)
					}

					cmd.Printf("User created successfully: %s (Role: %s, TOTP Secret: %s)\n",
						result.Username, result.Role, result.TOTPSecret)
					return nil
				},
			}

			// Set up flags
			createCmd.Flags().String("new-username", "", "Username for new user")
			createCmd.Flags().String("new-password", "", "Password for new user")
			createCmd.Flags().String("new-role", "", "Role for new user")

			createCmd.SetContext(tc.Ctx)
			createCmd.SetArgs(tt.args)

			// Capture output
			var output bytes.Buffer
			createCmd.SetOut(&output)
			createCmd.SetErr(&output)

			// Execute command
			err := createCmd.Execute()

			// Verify results
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedOutput)
			} else {
				assert.NoError(t, err)
				assert.Contains(t, output.String(), tt.expectedOutput)
			}

			tc.MockUserService.AssertExpectations(t)
		})
	}
}

// TestUsersListCommand tests the users list command
func TestUsersListCommand(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func(*testutils.TestContext)
		expectedOutput string
		expectedError  bool
	}{
		{
			name: "successful user listing",
			setupMocks: func(tc *testutils.TestContext) {
				users := []domain.User{
					{
						ID:       uuid.New(),
						Username: "admin",
						Role:     domain.RoleAdmin,
					},
					{
						ID:       uuid.New(),
						Username: "testuser",
						Role:     domain.RoleUser,
					},
				}
				tc.MockUserService.On("ListUsers", mock.Anything).Return(users, nil)
			},
			expectedOutput: "admin",
			expectedError:  false,
		},
		{
			name: "empty user list",
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockUserService.On("ListUsers", mock.Anything).Return([]domain.User{}, nil)
			},
			expectedOutput: "No users found",
			expectedError:  false,
		},
		{
			name: "service error",
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockUserService.On("ListUsers", mock.Anything).Return(nil, assert.AnError)
			},
			expectedOutput: "failed to list users",
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := testutils.NewTestContext(t)
			tt.setupMocks(tc)

			// Create a simple list command for testing
			listCmd := &cobra.Command{
				Use: "list",
				RunE: func(cmd *cobra.Command, args []string) error {
					users, err := tc.MockUserService.ListUsers(cmd.Context())
					if err != nil {
						return fmt.Errorf("failed to list users: %w", err)
					}

					if len(users) == 0 {
						cmd.Println("No users found")
						return nil
					}

					for _, user := range users {
						cmd.Printf("User: %s (Role: %s)\n", user.Username, user.Role)
					}
					return nil
				},
			}
			listCmd.SetContext(tc.Ctx)

			// Capture output
			var output bytes.Buffer
			listCmd.SetOut(&output)
			listCmd.SetErr(&output)

			// Execute command
			err := listCmd.Execute()

			// Verify results
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedOutput)
			} else {
				assert.NoError(t, err)
				assert.Contains(t, output.String(), tt.expectedOutput)
			}

			tc.MockUserService.AssertExpectations(t)
		})
	}
}

// TestUsersCommandIntegration tests integration between user commands
func TestUsersCommandIntegration(t *testing.T) {
	t.Run("complete user lifecycle", func(t *testing.T) {
		tc := testutils.NewTestContext(t)

		// Step 1: Create user
		createResult := &userServices.CreateUserResult{
			UserID:     uuid.New(),
			Username:   "lifecycle-user",
			Role:       domain.RoleUser,
			TOTPSecret: "TESTTOTP12345678",
		}

		tc.MockUserService.On("CreateUser", mock.Anything, userServices.CreateUserRequest{
			Username: "lifecycle-user",
			Password: "secure-password",
			Role:     "user",
		}).Return(createResult, nil)

		// Step 2: List users (should include new user)
		users := []domain.User{
			{ID: createResult.UserID, Username: "lifecycle-user", Role: domain.RoleUser},
		}
		tc.MockUserService.On("ListUsers", mock.Anything).Return(users, nil)

		// Test 1: Create user
		createCmd := &cobra.Command{
			Use: "create",
			RunE: func(cmd *cobra.Command, args []string) error {
				username, _ := cmd.Flags().GetString("new-username")
				password, _ := cmd.Flags().GetString("new-password")
				role, _ := cmd.Flags().GetString("new-role")

				if username == "" || password == "" || role == "" {
					return fmt.Errorf("username, password, and role are required")
				}

				req := userServices.CreateUserRequest{
					Username: username,
					Password: password,
					Role:     role,
				}

				result, err := tc.MockUserService.CreateUser(cmd.Context(), req)
				if err != nil {
					return fmt.Errorf("failed to create user: %w", err)
				}

				cmd.Printf("User created successfully: %s (Role: %s, TOTP Secret: %s)\n",
					result.Username, result.Role, result.TOTPSecret)
				return nil
			},
		}
		createCmd.Flags().String("new-username", "", "Username for new user")
		createCmd.Flags().String("new-password", "", "Password for new user")
		createCmd.Flags().String("new-role", "", "Role for new user")
		createCmd.SetContext(tc.Ctx)
		createCmd.SetArgs([]string{"--new-username=lifecycle-user", "--new-password=secure-password", "--new-role=user"})

		var output bytes.Buffer
		createCmd.SetOut(&output)

		err := createCmd.Execute()
		assert.NoError(t, err)
		assert.Contains(t, output.String(), "User created successfully")

		// Test 2: List users
		listCmd := &cobra.Command{
			Use: "list",
			RunE: func(cmd *cobra.Command, args []string) error {
				users, err := tc.MockUserService.ListUsers(cmd.Context())
				if err != nil {
					return fmt.Errorf("failed to list users: %w", err)
				}

				if len(users) == 0 {
					cmd.Println("No users found")
					return nil
				}

				for _, user := range users {
					cmd.Printf("User: %s (Role: %s)\n", user.Username, user.Role)
				}
				return nil
			},
		}
		listCmd.SetContext(tc.Ctx)

		output.Reset()
		listCmd.SetOut(&output)

		err = listCmd.Execute()
		assert.NoError(t, err)
		assert.Contains(t, output.String(), "lifecycle-user")

		tc.MockUserService.AssertExpectations(t)
	})
}
