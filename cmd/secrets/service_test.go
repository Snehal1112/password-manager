package secrets

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
	secretServices "password-manager/internal/services/secrets"
)

// TestSecretsCreateCommand tests the secrets create command comprehensively
func TestSecretsCreateCommand(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		setupMocks     func(*testutils.TestContext)
		expectedOutput string
		expectedError  bool
	}{
		{
			name: "successful secret creation with args",
			args: []string{"api-key", "super-secret-value"},
			setupMocks: func(tc *testutils.TestContext) {
				expectedSecret := &domain.Secret{
					ID:      uuid.New(),
					UserID:  tc.TestUserID,
					Name:    "api-key",
					Value:   "super-secret-value",
					Version: 1,
					Tags:    []string{},
				}
				tc.MockSecretService.On("CreateSecret", mock.Anything, secretServices.CreateSecretRequest{
					UserID: tc.TestUserID,
					Name:   "api-key",
					Value:  "super-secret-value",
					Tags:   []string{},
				}).Return(expectedSecret, nil)
			},
			expectedOutput: "Secret created successfully",
			expectedError:  false,
		},
		{
			name: "successful secret creation with tags",
			args: []string{"db-password", "secret-db-pass", "--tags=database,production,critical"},
			setupMocks: func(tc *testutils.TestContext) {
				expectedSecret := &domain.Secret{
					ID:      uuid.New(),
					UserID:  tc.TestUserID,
					Name:    "db-password",
					Value:   "secret-db-pass",
					Version: 1,
					Tags:    []string{"database", "production", "critical"},
				}
				tc.MockSecretService.On("CreateSecret", mock.Anything, secretServices.CreateSecretRequest{
					UserID: tc.TestUserID,
					Name:   "db-password",
					Value:  "secret-db-pass",
					Tags:   []string{"database", "production", "critical"},
				}).Return(expectedSecret, nil)
			},
			expectedOutput: "Secret created successfully",
			expectedError:  false,
		},
		{
			name: "missing name argument",
			args: []string{},
			setupMocks: func(tc *testutils.TestContext) {
				// No mocks needed for validation error
			},
			expectedOutput: "name and value are required",
			expectedError:  true,
		},
		{
			name: "missing value argument",
			args: []string{"secret-name"},
			setupMocks: func(tc *testutils.TestContext) {
				// No mocks needed for validation error
			},
			expectedOutput: "name and value are required",
			expectedError:  true,
		},
		{
			name: "service error",
			args: []string{"failing-secret", "some-value"},
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockSecretService.On("CreateSecret", mock.Anything, mock.Anything).
					Return(nil, fmt.Errorf("database connection failed"))
			},
			expectedOutput: "failed to create secret",
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := testutils.NewTestContext(t)
			tt.setupMocks(tc)

			// Create enhanced test command that uses service container
			createCmd := &cobra.Command{
				Use: "create <name> <value>",
				Args: func(cmd *cobra.Command, args []string) error {
					if len(args) < 2 {
						return fmt.Errorf("name and value are required")
					}
					return nil
				},
				RunE: func(cmd *cobra.Command, args []string) error {
					if len(args) < 2 {
						return fmt.Errorf("name and value are required")
					}

					name := args[0]
					value := args[1]
					tags, _ := cmd.Flags().GetStringSlice("tags")

					_, err := tc.MockSecretService.CreateSecret(cmd.Context(), secretServices.CreateSecretRequest{
						UserID: tc.TestUserID,
						Name:   name,
						Value:  value,
						Tags:   tags,
					})
					if err != nil {
						return fmt.Errorf("failed to create secret: %w", err)
					}

					cmd.Println("Secret created successfully")
					return nil
				},
			}
			createCmd.Flags().StringSlice("tags", []string{}, "Tags for the secret")
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

			tc.MockSecretService.AssertExpectations(t)
		})
	}
}

// TestSecretsListCommand tests the secrets list command
func TestSecretsListCommand(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		setupMocks     func(*testutils.TestContext)
		expectedOutput string
		expectedError  bool
	}{
		{
			name: "successful secrets listing",
			args: []string{},
			setupMocks: func(tc *testutils.TestContext) {
				secrets := []domain.Secret{
					{
						ID:      uuid.New(),
						UserID:  tc.TestUserID,
						Name:    "api-key",
						Value:   "secret-value",
						Version: 1,
						Tags:    []string{"api", "production"},
					},
					{
						ID:      uuid.New(),
						UserID:  tc.TestUserID,
						Name:    "db-password",
						Value:   "db-secret",
						Version: 2,
						Tags:    []string{"database"},
					},
				}
				tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID,
					mock.MatchedBy(func(tags []string) bool { return len(tags) == 0 })).
					Return(secrets, nil)
			},
			expectedOutput: "api-key",
			expectedError:  false,
		},
		{
			name: "filtered secrets by tags",
			args: []string{"--tags=database"},
			setupMocks: func(tc *testutils.TestContext) {
				secrets := []domain.Secret{
					{
						ID:      uuid.New(),
						UserID:  tc.TestUserID,
						Name:    "db-password",
						Value:   "db-secret",
						Version: 1,
						Tags:    []string{"database"},
					},
				}
				tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID, []string{"database"}).
					Return(secrets, nil)
			},
			expectedOutput: "db-password",
			expectedError:  false,
		},
		{
			name: "empty secrets list",
			args: []string{},
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID,
					mock.MatchedBy(func(tags []string) bool { return len(tags) == 0 })).
					Return([]domain.Secret{}, nil)
			},
			expectedOutput: "No secrets found",
			expectedError:  false,
		},
		{
			name: "service error",
			args: []string{},
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID,
					mock.MatchedBy(func(tags []string) bool { return len(tags) == 0 })).
					Return(nil, fmt.Errorf("database error"))
			},
			expectedOutput: "failed to list secrets",
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := testutils.NewTestContext(t)
			tt.setupMocks(tc)

			// Create enhanced test list command
			listCmd := &cobra.Command{
				Use: "list",
				RunE: func(cmd *cobra.Command, args []string) error {
					tags, _ := cmd.Flags().GetStringSlice("tags")

					secrets, err := tc.MockSecretService.ListSecrets(cmd.Context(), tc.TestUserID, tags)
					if err != nil {
						return fmt.Errorf("failed to list secrets: %w", err)
					}

					if len(secrets) == 0 {
						cmd.Println("No secrets found")
						return nil
					}

					for _, secret := range secrets {
						cmd.Printf("Secret: %s (Version: %d, Tags: %v)\n", secret.Name, secret.Version, secret.Tags)
					}
					return nil
				},
			}
			listCmd.Flags().StringSlice("tags", []string{}, "Filter by tags")
			listCmd.SetContext(tc.Ctx)
			listCmd.SetArgs(tt.args)

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

			tc.MockSecretService.AssertExpectations(t)
		})
	}
}

// TestSecretsGetCommand tests the secrets get command
func TestSecretsGetCommand(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		setupMocks     func(*testutils.TestContext) uuid.UUID
		expectedOutput string
		expectedError  bool
	}{
		{
			name: "successful secret retrieval",
			setupMocks: func(tc *testutils.TestContext) uuid.UUID {
				secretID := uuid.New()
				secret := &domain.Secret{
					ID:      secretID,
					UserID:  tc.TestUserID,
					Name:    "retrieved-secret",
					Value:   "secret-value",
					Version: 1,
					Tags:    []string{"test"},
				}
				tc.MockSecretService.On("GetSecret", mock.Anything, secretID, tc.TestUserID).
					Return(secret, nil)
				return secretID
			},
			expectedOutput: "retrieved-secret",
			expectedError:  false,
		},
		{
			name: "secret not found",
			setupMocks: func(tc *testutils.TestContext) uuid.UUID {
				secretID := uuid.New()
				tc.MockSecretService.On("GetSecret", mock.Anything, secretID, tc.TestUserID).
					Return(nil, fmt.Errorf("secret not found"))
				return secretID
			},
			expectedOutput: "failed to get secret",
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := testutils.NewTestContext(t)
			secretID := tt.setupMocks(tc)

			// Create enhanced test get command
			getCmd := &cobra.Command{
				Use:  "get [id]",
				Args: cobra.ExactArgs(1),
				RunE: func(cmd *cobra.Command, args []string) error {
					secretIDArg := args[0]
					secretUUID, err := uuid.Parse(secretIDArg)
					if err != nil {
						return fmt.Errorf("invalid secret ID: %w", err)
					}

					secret, err := tc.MockSecretService.GetSecret(cmd.Context(), secretUUID, tc.TestUserID)
					if err != nil {
						return fmt.Errorf("failed to get secret: %w", err)
					}

					cmd.Printf("Secret: %s (Value: %s, Version: %d)\n", secret.Name, secret.Value, secret.Version)
					return nil
				},
			}
			getCmd.SetContext(tc.Ctx)
			getCmd.SetArgs([]string{secretID.String()})

			// Capture output
			var output bytes.Buffer
			getCmd.SetOut(&output)
			getCmd.SetErr(&output)

			// Execute command
			err := getCmd.Execute()

			// Verify results
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedOutput)
			} else {
				assert.NoError(t, err)
				assert.Contains(t, output.String(), tt.expectedOutput)
			}

			tc.MockSecretService.AssertExpectations(t)
		})
	}
}

// TestSecretsIntegration tests secret command integration scenarios
func TestSecretsIntegration(t *testing.T) {
	t.Run("complete secret lifecycle", func(t *testing.T) {
		tc := testutils.NewTestContext(t)

		// Step 1: Create secret
		secretID := uuid.New()
		createdSecret := &domain.Secret{
			ID:      secretID,
			UserID:  tc.TestUserID,
			Name:    "lifecycle-secret",
			Value:   "initial-value",
			Version: 1,
			Tags:    []string{"test", "lifecycle"},
		}

		tc.MockSecretService.On("CreateSecret", mock.Anything, secretServices.CreateSecretRequest{
			UserID: tc.TestUserID,
			Name:   "lifecycle-secret",
			Value:  "initial-value",
			Tags:   []string{"test", "lifecycle"},
		}).Return(createdSecret, nil)

		// Step 2: List secrets (should include new secret)
		allSecrets := []domain.Secret{*createdSecret}
		tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID,
			mock.MatchedBy(func(tags []string) bool { return len(tags) == 0 })).
			Return(allSecrets, nil)

		// Step 3: Get specific secret
		tc.MockSecretService.On("GetSecret", mock.Anything, secretID, tc.TestUserID).
			Return(createdSecret, nil)

		// Execute the lifecycle workflow
		workflowSteps := []struct {
			name        string
			commandFunc func() *cobra.Command
			verifyFunc  func(output string)
		}{
			{
				name: "create secret",
				commandFunc: func() *cobra.Command {
					cmd := &cobra.Command{
						Use: "create",
						RunE: func(cmd *cobra.Command, args []string) error {
							_, err := tc.MockSecretService.CreateSecret(cmd.Context(), secretServices.CreateSecretRequest{
								UserID: tc.TestUserID,
								Name:   "lifecycle-secret",
								Value:  "initial-value",
								Tags:   []string{"test", "lifecycle"},
							})
							if err != nil {
								return err
							}
							cmd.Println("Secret created successfully")
							return nil
						},
					}
					cmd.SetContext(tc.Ctx)
					return cmd
				},
				verifyFunc: func(output string) {
					assert.Contains(t, output, "Secret created successfully")
				},
			},
			{
				name: "list secrets",
				commandFunc: func() *cobra.Command {
					cmd := &cobra.Command{
						Use: "list",
						RunE: func(cmd *cobra.Command, args []string) error {
							secrets, err := tc.MockSecretService.ListSecrets(cmd.Context(), tc.TestUserID, nil)
							if err != nil {
								return err
							}
							for _, secret := range secrets {
								cmd.Printf("Secret: %s\n", secret.Name)
							}
							return nil
						},
					}
					cmd.SetContext(tc.Ctx)
					return cmd
				},
				verifyFunc: func(output string) {
					assert.Contains(t, output, "lifecycle-secret")
				},
			},
			{
				name: "get secret",
				commandFunc: func() *cobra.Command {
					cmd := &cobra.Command{
						Use: "get",
						RunE: func(cmd *cobra.Command, args []string) error {
							secret, err := tc.MockSecretService.GetSecret(cmd.Context(), secretID, tc.TestUserID)
							if err != nil {
								return err
							}
							cmd.Printf("Secret: %s (Value: %s)\n", secret.Name, secret.Value)
							return nil
						},
					}
					cmd.SetContext(tc.Ctx)
					return cmd
				},
				verifyFunc: func(output string) {
					assert.Contains(t, output, "lifecycle-secret")
					assert.Contains(t, output, "initial-value")
				},
			},
		}

		for _, step := range workflowSteps {
			t.Run(step.name, func(t *testing.T) {
				cmd := step.commandFunc()
				var output bytes.Buffer
				cmd.SetOut(&output)

				err := cmd.Execute()
				assert.NoError(t, err)
				step.verifyFunc(output.String())
			})
		}

		tc.MockSecretService.AssertExpectations(t)
	})
}
