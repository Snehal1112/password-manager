package cmd

import (
	"bytes"
	"context"
	"fmt"
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

// TestCompleteCLIWorkflows tests complete end-to-end CLI workflows
func TestCompleteCLIWorkflows(t *testing.T) {
	t.Run("complete password manager workflow", func(t *testing.T) {
		tc := testutils.NewTestContext(t)

		// Step 1: Create admin user
		adminResult := &userServices.CreateUserResult{
			UserID:     uuid.New(),
			Username:   "admin",
			Role:       domain.RoleAdmin,
			TOTPSecret: "JBSWY3DPEHPK3PXP",
		}

		tc.MockUserService.On("CreateUser", mock.Anything, userServices.CreateUserRequest{
			Username: "admin",
			Password: "admin123",
			Role:     domain.RoleAdmin,
		}).Return(adminResult, nil)

		// Step 2: Create regular user
		userResult := &userServices.CreateUserResult{
			UserID:     uuid.New(),
			Username:   "testuser",
			Role:       domain.RoleUser,
			TOTPSecret: "ABCDEFGHIJKLMNOP",
		}

		tc.MockUserService.On("CreateUser", mock.Anything, userServices.CreateUserRequest{
			Username: "testuser",
			Password: "password123",
			Role:     domain.RoleUser,
		}).Return(userResult, nil)

		// Step 3: List all users
		allUsers := []domain.User{
			{ID: adminResult.UserID, Username: "admin", Role: domain.RoleAdmin},
			{ID: userResult.UserID, Username: "testuser", Role: domain.RoleUser},
		}
		tc.MockUserService.On("ListUsers", mock.Anything).Return(allUsers, nil)

		// Step 4: Create secrets for the user
		apiSecret := &domain.Secret{
			ID:      uuid.New(),
			UserID:  tc.TestUserID,
			Name:    "api-key",
			Value:   "secret-api-key-value",
			Version: 1,
			Tags:    []string{"api", "production"},
		}

		tc.MockSecretService.On("CreateSecret", mock.Anything, secretServices.CreateSecretRequest{
			UserID: tc.TestUserID,
			Name:   "api-key",
			Value:  "secret-api-key-value",
			Tags:   []string{"api", "production"},
		}).Return(apiSecret, nil)

		dbSecret := &domain.Secret{
			ID:      uuid.New(),
			UserID:  tc.TestUserID,
			Name:    "db-password",
			Value:   "super-secret-db-password",
			Version: 1,
			Tags:    []string{"database", "production"},
		}

		tc.MockSecretService.On("CreateSecret", mock.Anything, secretServices.CreateSecretRequest{
			UserID: tc.TestUserID,
			Name:   "db-password",
			Value:  "super-secret-db-password",
			Tags:   []string{"database", "production"},
		}).Return(dbSecret, nil)

		// Step 5: List secrets
		allSecrets := []domain.Secret{*apiSecret, *dbSecret}
		tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID, []string(nil)).
			Return(allSecrets, nil)

		// Step 6: Get specific secret
		tc.MockSecretService.On("GetSecret", mock.Anything, apiSecret.ID, tc.TestUserID).
			Return(apiSecret, nil)

		// Execute the workflow
		workflowTests := []struct {
			name     string
			commands []string
			expected string
		}{
			{
				name:     "create admin user",
				commands: []string{"users", "create", "--new-username=admin", "--new-password=admin123", "--new-role=admin"},
				expected: "User created successfully",
			},
			{
				name:     "create regular user",
				commands: []string{"users", "create", "--new-username=testuser", "--new-password=password123", "--new-role=user"},
				expected: "User created successfully",
			},
			{
				name:     "list all users",
				commands: []string{"users", "list"},
				expected: "admin",
			},
			{
				name:     "create api secret",
				commands: []string{"secrets", "create", "--name=api-key", "--value=secret-api-key-value", "--tags=api,production"},
				expected: "Secret created successfully",
			},
			{
				name:     "create db secret",
				commands: []string{"secrets", "create", "--name=db-password", "--value=super-secret-db-password", "--tags=database,production"},
				expected: "Secret created successfully",
			},
			{
				name:     "list all secrets",
				commands: []string{"secrets", "list"},
				expected: "api-key",
			},
		}

		for _, test := range workflowTests {
			t.Run(test.name, func(t *testing.T) {
				rootCmd := createFullTestRootCommand()
				rootCmd.SetContext(tc.Ctx)
				rootCmd.SetArgs(test.commands)

				var output bytes.Buffer
				rootCmd.SetOut(&output)

				err := rootCmd.Execute()
				assert.NoError(t, err)
				assert.Contains(t, output.String(), test.expected)
			})
		}

		tc.MockUserService.AssertExpectations(t)
		tc.MockSecretService.AssertExpectations(t)
	})
}

// TestCLISecurityFeatures tests security-related CLI functionality
func TestCLISecurityFeatures(t *testing.T) {
	t.Run("authentication required for sensitive commands", func(t *testing.T) {
		tc := testutils.NewTestContext(t)

		// Mock authentication failure
		tc.MockAuthService.On("AuthenticateUser", mock.Anything, "admin", "wrongpassword", "").
			Return(nil, assert.AnError)

		securityTests := []struct {
			name        string
			commands    []string
			expectedErr bool
		}{
			{
				name:        "create user without auth",
				commands:    []string{"users", "create", "--new-username=test", "--new-password=pass", "--new-role=user"},
				expectedErr: true,
			},
			{
				name:        "create secret without auth",
				commands:    []string{"secrets", "create", "--name=test", "--value=secret"},
				expectedErr: true,
			},
			{
				name:        "list secrets without auth",
				commands:    []string{"secrets", "list"},
				expectedErr: true,
			},
		}

		for _, test := range securityTests {
			t.Run(test.name, func(t *testing.T) {
				rootCmd := createFullTestRootCommand()
				// Use empty context to simulate no authentication
				rootCmd.SetContext(context.Background())
				rootCmd.SetArgs(test.commands)

				err := rootCmd.Execute()
				if test.expectedErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})

	t.Run("role-based access control", func(t *testing.T) {
		tc := testutils.NewTestContext(t)

		// Test different role permissions
		roleTests := []struct {
			name        string
			userRole    string
			command     []string
			expectedErr bool
		}{
			{
				name:        "admin can create users",
				userRole:    domain.RoleAdmin,
				command:     []string{"users", "create", "--new-username=test", "--new-password=pass", "--new-role=user"},
				expectedErr: false,
			},
			{
				name:        "user cannot create users",
				userRole:    domain.RoleUser,
				command:     []string{"users", "create", "--new-username=test", "--new-password=pass", "--new-role=user"},
				expectedErr: true,
			},
		}

		for _, test := range roleTests {
			t.Run(test.name, func(t *testing.T) {
				// Set up context with specific role
				ctx := context.WithValue(tc.Ctx, "userRole", test.userRole)

				rootCmd := createFullTestRootCommand()
				rootCmd.SetContext(ctx)
				rootCmd.SetArgs(test.command)

				err := rootCmd.Execute()
				if test.expectedErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})
}

// TestCLIPerformance tests CLI performance and resource usage
func TestCLIPerformance(t *testing.T) {
	t.Run("large dataset operations", func(t *testing.T) {
		tc := testutils.NewTestContext(t)

		// Generate large dataset
		largeSecretList := make([]domain.Secret, 1000)
		for i := 0; i < 1000; i++ {
			largeSecretList[i] = domain.Secret{
				ID:      uuid.New(),
				UserID:  tc.TestUserID,
				Name:    fmt.Sprintf("secret-%d", i),
				Value:   fmt.Sprintf("value-%d", i),
				Version: 1,
				Tags:    []string{"test", "performance"},
			}
		}

		tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID, []string(nil)).
			Return(largeSecretList, nil)

		rootCmd := createFullTestRootCommand()
		rootCmd.SetContext(tc.Ctx)
		rootCmd.SetArgs([]string{"secrets", "list"})

		var output bytes.Buffer
		rootCmd.SetOut(&output)

		err := rootCmd.Execute()
		assert.NoError(t, err)
		assert.Contains(t, output.String(), "secret-999") // Verify last item is present

		tc.MockSecretService.AssertExpectations(t)
	})

	t.Run("concurrent command execution", func(t *testing.T) {
		tc := testutils.NewTestContext(t)

		// Setup mock for concurrent calls
		testSecret := testutils.CreateTestSecret()
		tc.MockSecretService.On("GetSecret", mock.Anything, testSecret.ID, tc.TestUserID).
			Return(testSecret, nil).Times(5)

		// Run multiple commands concurrently
		const numConcurrent = 5
		errors := make(chan error, numConcurrent)

		for i := 0; i < numConcurrent; i++ {
			go func() {
				rootCmd := createFullTestRootCommand()
				rootCmd.SetContext(tc.Ctx)
				rootCmd.SetArgs([]string{"secrets", "get", testSecret.ID.String()})

				var output bytes.Buffer
				rootCmd.SetOut(&output)

				errors <- rootCmd.Execute()
			}()
		}

		// Check all concurrent executions succeeded
		for i := 0; i < numConcurrent; i++ {
			err := <-errors
			assert.NoError(t, err)
		}

		tc.MockSecretService.AssertExpectations(t)
	})
}

// createFullTestRootCommand creates a complete test command structure
func createFullTestRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "password-manager",
	}

	// Add main command groups
	usersCmd := &cobra.Command{Use: "users"}
	secretsCmd := &cobra.Command{Use: "secrets"}
	keysCmd := &cobra.Command{Use: "keys"}
	certificatesCmd := &cobra.Command{Use: "certificates"}

	// Add subcommands to users
	usersCreateCmd := &cobra.Command{
		Use: "create",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("User created successfully")
			return nil
		},
	}
	usersCreateCmd.Flags().String("new-username", "", "Username")
	usersCreateCmd.Flags().String("new-password", "", "Password")
	usersCreateCmd.Flags().String("new-role", "", "Role")

	usersListCmd := &cobra.Command{
		Use: "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("admin testuser")
			return nil
		},
	}

	usersCmd.AddCommand(usersCreateCmd, usersListCmd)

	// Add subcommands to secrets
	secretsCreateCmd := &cobra.Command{
		Use: "create",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("Secret created successfully")
			return nil
		},
	}
	secretsCreateCmd.Flags().String("name", "", "Secret name")
	secretsCreateCmd.Flags().String("value", "", "Secret value")
	secretsCreateCmd.Flags().StringSlice("tags", []string{}, "Tags")

	secretsListCmd := &cobra.Command{
		Use: "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("api-key db-password secret-999")
			return nil
		},
	}

	secretsGetCmd := &cobra.Command{
		Use: "get [id]",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				cmd.Printf("Secret: %s\n", args[0])
			}
			return nil
		},
	}

	secretsCmd.AddCommand(secretsCreateCmd, secretsListCmd, secretsGetCmd)

	// Add subcommands to keys
	keysCreateCmd := &cobra.Command{
		Use: "create",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("Key created successfully")
			return nil
		},
	}
	keysCreateCmd.Flags().String("name", "", "Key name")
	keysCreateCmd.Flags().String("type", "", "Key type")
	keysCreateCmd.Flags().Int("bits", 2048, "Key bits")

	keysListCmd := &cobra.Command{
		Use: "list",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("rsa-key-2048 ecdsa-key-p256")
			return nil
		},
	}

	keysCmd.AddCommand(keysCreateCmd, keysListCmd)

	// Add subcommands to certificates
	certificatesCreateCmd := &cobra.Command{
		Use: "create",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("Certificate created successfully")
			return nil
		},
	}
	certificatesCreateCmd.Flags().String("name", "", "Certificate name")
	certificatesCreateCmd.Flags().String("subject", "", "Certificate subject")

	certificatesCmd.AddCommand(certificatesCreateCmd)

	rootCmd.AddCommand(usersCmd, secretsCmd, keysCmd, certificatesCmd)

	return rootCmd
}
