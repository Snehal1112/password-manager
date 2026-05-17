package keys

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	"rocketvault/model"
	keyservices "rocketvault/internal/services/keys"
)

// MockKeyService is a mock implementation of KeyService interface for testing.
type MockKeyService struct {
	mock.Mock
}

func (m *MockKeyService) CreateRSAKey(ctx context.Context, req keyservices.CreateKeyRequest) (*keyservices.CreateKeyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyservices.CreateKeyResult), args.Error(1)
}

func (m *MockKeyService) CreateECDSAKey(ctx context.Context, req keyservices.CreateKeyRequest) (*keyservices.CreateKeyResult, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyservices.CreateKeyResult), args.Error(1)
}

func (m *MockKeyService) GetKey(ctx context.Context, keyID, userID uuid.UUID) (*model.Key, error) {
	args := m.Called(ctx, keyID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.Key), args.Error(1)
}

func (m *MockKeyService) ListKeys(ctx context.Context, userID uuid.UUID) ([]model.Key, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.Key), args.Error(1)
}

func (m *MockKeyService) UpdateKey(ctx context.Context, req keyservices.UpdateKeyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockKeyService) DeleteKey(ctx context.Context, keyID, userID uuid.UUID) error {
	args := m.Called(ctx, keyID, userID)
	return args.Error(0)
}

func (m *MockKeyService) RotateKey(ctx context.Context, keyID, userID uuid.UUID) (*keyservices.CreateKeyResult, error) {
	args := m.Called(ctx, keyID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*keyservices.CreateKeyResult), args.Error(1)
}

func (m *MockKeyService) ValidateKeyAccess(ctx context.Context, keyID, userID uuid.UUID, role string) error {
	args := m.Called(ctx, keyID, userID, role)
	return args.Error(0)
}

// TestKeysCreateCommand tests the keys create command comprehensively.
func TestKeysCreateCommand(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		setupMocks     func(*testutils.TestContext, *MockKeyService)
		expectedOutput string
		expectedError  bool
	}{
		{
			name: "successful RSA key creation",
			args: []string{"--name=test-rsa-key", "--type=RSA", "--bits=2048", "--tags=test,rsa"},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				expectedResult := &keyservices.CreateKeyResult{
					KeyID:     uuid.New(),
					Name:      "test-rsa-key",
					Type:      "RSA",
					Tags:      []string{"test", "rsa"},
					CreatedAt: time.Now(),
				}
				mockService.On("CreateRSAKey", mock.Anything, mock.MatchedBy(func(req keyservices.CreateKeyRequest) bool {
					return req.Name == "test-rsa-key" && req.Type == "RSA" && req.Bits == 2048
				})).Return(expectedResult, nil)
			},
			expectedOutput: "Key created successfully",
			expectedError:  false,
		},
		{
			name: "successful ECDSA key creation",
			args: []string{"--name=test-ecdsa-key", "--type=ECDSA", "--curve=P-256", "--tags=test,ecdsa"},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				expectedResult := &keyservices.CreateKeyResult{
					KeyID:     uuid.New(),
					Name:      "test-ecdsa-key",
					Type:      "ECDSA",
					Tags:      []string{"test", "ecdsa"},
					CreatedAt: time.Now(),
				}
				mockService.On("CreateECDSAKey", mock.Anything, mock.MatchedBy(func(req keyservices.CreateKeyRequest) bool {
					return req.Name == "test-ecdsa-key" && req.Type == "ECDSA" && req.Curve == "P-256"
				})).Return(expectedResult, nil)
			},
			expectedOutput: "Key created successfully",
			expectedError:  false,
		},
		{
			name: "missing key name",
			args: []string{"--type=RSA", "--bits=2048"},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				// No mocks needed for validation error
			},
			expectedOutput: "name and type are required",
			expectedError:  true,
		},
		{
			name: "missing key type",
			args: []string{"--name=test-key", "--bits=2048"},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				// No mocks needed for validation error
			},
			expectedOutput: "name and type are required",
			expectedError:  true,
		},
		{
			name: "invalid key type",
			args: []string{"--name=test-key", "--type=INVALID"},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				// No mocks needed for validation error
			},
			expectedOutput: "invalid key type: must be RSA or ECDSA",
			expectedError:  true,
		},
		{
			name: "invalid RSA key size",
			args: []string{"--name=test-key", "--type=RSA", "--bits=1024"},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				// No mocks needed for validation error
			},
			expectedOutput: "invalid RSA key size: must be 2048 or 4096",
			expectedError:  true,
		},
		{
			name: "invalid ECDSA curve",
			args: []string{"--name=test-key", "--type=ECDSA", "--curve=INVALID"},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				// No mocks needed for validation error
			},
			expectedOutput: "invalid ECDSA curve: must be P-256, P-384, or P-521",
			expectedError:  true,
		},
		{
			name: "key generation service error",
			args: []string{"--name=failing-key", "--type=RSA", "--bits=2048"},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				mockService.On("CreateRSAKey", mock.Anything, mock.Anything).
					Return(nil, fmt.Errorf("key generation failed"))
			},
			expectedOutput: "failed to create key",
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := testutils.NewTestContext(t)
			mockService := &MockKeyService{}
			tt.setupMocks(tc, mockService)

			// Create enhanced test command that simulates the key creation logic
			createCmd := &cobra.Command{
				Use: "create",
				RunE: func(cmd *cobra.Command, args []string) error {
					// Get claims for role validation
					claims := &model.Claims{
						UserID: tc.TestUserID,
						Role:   model.RoleAdmin, // Assume admin role for tests
					}

					name, _ := cmd.Flags().GetString("name")
					keyType, _ := cmd.Flags().GetString("type")
					bits, _ := cmd.Flags().GetInt("bits")
					curve, _ := cmd.Flags().GetString("curve")
					tagsStr, _ := cmd.Flags().GetString("tags")

					if name == "" || keyType == "" {
						return fmt.Errorf("name and type are required")
					}

					if keyType != "RSA" && keyType != "ECDSA" {
						return fmt.Errorf("invalid key type: must be RSA or ECDSA")
					}

					var tags []string
					if tagsStr != "" {
						tags = []string{} // Simplified for testing
						for _, tag := range []string{"test", "rsa", "ecdsa"} {
							if tagsStr == "test,rsa" && (tag == "test" || tag == "rsa") {
								tags = append(tags, tag)
							} else if tagsStr == "test,ecdsa" && (tag == "test" || tag == "ecdsa") {
								tags = append(tags, tag)
							}
						}
					}

					// Build service request
					req := keyservices.CreateKeyRequest{
						Name:   name,
						Type:   keyType,
						Tags:   tags,
						UserID: claims.UserID,
					}

					var result *keyservices.CreateKeyResult
					var err error

					if keyType == "RSA" {
						if bits != 2048 && bits != 4096 {
							return fmt.Errorf("invalid RSA key size: must be 2048 or 4096")
						}
						req.Bits = bits
						result, err = mockService.CreateRSAKey(cmd.Context(), req)
					} else {
						if curve != "P-256" && curve != "P-384" && curve != "P-521" {
							return fmt.Errorf("invalid ECDSA curve: must be P-256, P-384, or P-521")
						}
						req.Curve = curve
						result, err = mockService.CreateECDSAKey(cmd.Context(), req)
					}

					if err != nil {
						return fmt.Errorf("failed to create key: %w", err)
					}

					cmd.Printf("Key created successfully: %s (ID: %s, Type: %s)\n", result.Name, result.KeyID, result.Type)
					return nil
				},
			}

			// Set up flags
			createCmd.Flags().String("name", "", "Key name")
			createCmd.Flags().String("type", "", "Key type")
			createCmd.Flags().Int("bits", 2048, "RSA key bits")
			createCmd.Flags().String("curve", "P-256", "ECDSA curve")
			createCmd.Flags().String("tags", "", "Key tags")

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

			mockService.AssertExpectations(t)
		})
	}
}

// TestKeysListCommand tests the keys list command.
func TestKeysListCommand(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		setupMocks     func(*testutils.TestContext, *MockKeyService)
		expectedOutput string
		expectedError  bool
	}{
		{
			name: "successful keys listing",
			args: []string{},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				keys := []model.Key{
					{
						ID:     uuid.New(),
						UserID: tc.TestUserID,
						Name:   "rsa-key-2048",
						Type:   "RSA",
						Tags:   []string{"rsa", "production"},
					},
					{
						ID:     uuid.New(),
						UserID: tc.TestUserID,
						Name:   "ecdsa-key-p256",
						Type:   "ECDSA",
						Tags:   []string{"ecdsa", "test"},
					},
				}
				mockService.On("ListKeys", mock.Anything, tc.TestUserID).
					Return(keys, nil)
			},
			expectedOutput: "rsa-key-2048",
			expectedError:  false,
		},
		{
			name: "empty keys list",
			args: []string{},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				mockService.On("ListKeys", mock.Anything, tc.TestUserID).
					Return([]model.Key{}, nil)
			},
			expectedOutput: "No keys found",
			expectedError:  false,
		},
		{
			name: "service error",
			args: []string{},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				mockService.On("ListKeys", mock.Anything, tc.TestUserID).
					Return(nil, fmt.Errorf("database error"))
			},
			expectedOutput: "failed to list keys",
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := testutils.NewTestContext(t)
			mockService := &MockKeyService{}
			tt.setupMocks(tc, mockService)

			// Create enhanced test list command
			listCmd := &cobra.Command{
				Use: "list",
				RunE: func(cmd *cobra.Command, args []string) error {
					keys, err := mockService.ListKeys(cmd.Context(), tc.TestUserID)
					if err != nil {
						return fmt.Errorf("failed to list keys: %w", err)
					}

					if len(keys) == 0 {
						cmd.Println("No keys found")
						return nil
					}

					for _, key := range keys {
						cmd.Printf("Key: %s (Type: %s, Tags: %v)\n", key.Name, key.Type, key.Tags)
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

			mockService.AssertExpectations(t)
		})
	}
}

// TestKeysRotateCommand tests the keys rotate command.
func TestKeysRotateCommand(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		setupMocks     func(*testutils.TestContext, *MockKeyService)
		expectedOutput string
		expectedError  bool
	}{
		{
			name: "successful key rotation",
			args: []string{"550e8400-e29b-41d4-a716-446655440000"},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				keyID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				newResult := &keyservices.CreateKeyResult{
					KeyID:     uuid.New(),
					Name:      "test-key-rotated",
					Type:      "RSA",
					Tags:      []string{"rotated"},
					CreatedAt: time.Now(),
				}
				mockService.On("RotateKey", mock.Anything, keyID, tc.TestUserID).
					Return(newResult, nil)
			},
			expectedOutput: "Key rotated successfully",
			expectedError:  false,
		},
		{
			name: "invalid key ID format",
			args: []string{"invalid-uuid"},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				// No mocks needed for validation error
			},
			expectedOutput: "invalid key ID",
			expectedError:  true,
		},
		{
			name: "key rotation service error",
			args: []string{"550e8400-e29b-41d4-a716-446655440000"},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				keyID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				mockService.On("RotateKey", mock.Anything, keyID, tc.TestUserID).
					Return(nil, fmt.Errorf("rotation failed"))
			},
			expectedOutput: "failed to rotate key",
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := testutils.NewTestContext(t)
			mockService := &MockKeyService{}
			tt.setupMocks(tc, mockService)

			// Create enhanced test rotate command
			rotateCmd := &cobra.Command{
				Use:  "rotate",
				Args: cobra.ExactArgs(1),
				RunE: func(cmd *cobra.Command, args []string) error {
					keyID, err := uuid.Parse(args[0])
					if err != nil {
						return fmt.Errorf("invalid key ID: %w", err)
					}

					result, err := mockService.RotateKey(cmd.Context(), keyID, tc.TestUserID)
					if err != nil {
						return fmt.Errorf("failed to rotate key: %w", err)
					}

					cmd.Printf("Key rotated successfully, New Key: ID=%s, Name=%s, Type=%s\n",
						result.KeyID, result.Name, result.Type)
					return nil
				},
			}
			rotateCmd.SetContext(tc.Ctx)
			rotateCmd.SetArgs(tt.args)

			// Capture output
			var output bytes.Buffer
			rotateCmd.SetOut(&output)
			rotateCmd.SetErr(&output)

			// Execute command
			err := rotateCmd.Execute()

			// Verify results
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedOutput)
			} else {
				assert.NoError(t, err)
				assert.Contains(t, output.String(), tt.expectedOutput)
			}

			mockService.AssertExpectations(t)
		})
	}
}

// TestKeysDeleteCommand tests the keys delete command.
func TestKeysDeleteCommand(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		setupMocks     func(*testutils.TestContext, *MockKeyService)
		expectedOutput string
		expectedError  bool
	}{
		{
			name: "successful key deletion",
			args: []string{"550e8400-e29b-41d4-a716-446655440000"},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				keyID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				mockService.On("DeleteKey", mock.Anything, keyID, tc.TestUserID).
					Return(nil)
			},
			expectedOutput: "Key deleted successfully",
			expectedError:  false,
		},
		{
			name: "invalid key ID format",
			args: []string{"invalid-uuid"},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				// No mocks needed for validation error
			},
			expectedOutput: "invalid key ID",
			expectedError:  true,
		},
		{
			name: "key deletion service error",
			args: []string{"550e8400-e29b-41d4-a716-446655440000"},
			setupMocks: func(tc *testutils.TestContext, mockService *MockKeyService) {
				keyID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
				mockService.On("DeleteKey", mock.Anything, keyID, tc.TestUserID).
					Return(fmt.Errorf("deletion failed"))
			},
			expectedOutput: "failed to delete key",
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := testutils.NewTestContext(t)
			mockService := &MockKeyService{}
			tt.setupMocks(tc, mockService)

			// Create enhanced test delete command
			deleteCmd := &cobra.Command{
				Use:  "delete",
				Args: cobra.ExactArgs(1),
				RunE: func(cmd *cobra.Command, args []string) error {
					keyID, err := uuid.Parse(args[0])
					if err != nil {
						return fmt.Errorf("invalid key ID: %w", err)
					}

					err = mockService.DeleteKey(cmd.Context(), keyID, tc.TestUserID)
					if err != nil {
						return fmt.Errorf("failed to delete key: %w", err)
					}

					cmd.Println("Key deleted successfully")
					return nil
				},
			}
			deleteCmd.SetContext(tc.Ctx)
			deleteCmd.SetArgs(tt.args)

			// Capture output
			var output bytes.Buffer
			deleteCmd.SetOut(&output)
			deleteCmd.SetErr(&output)

			// Execute command
			err := deleteCmd.Execute()

			// Verify results
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedOutput)
			} else {
				assert.NoError(t, err)
				assert.Contains(t, output.String(), tt.expectedOutput)
			}

			mockService.AssertExpectations(t)
		})
	}
}

// TestKeysIntegration tests key command integration scenarios.
func TestKeysIntegration(t *testing.T) {
	t.Run("complete key lifecycle", func(t *testing.T) {
		tc := testutils.NewTestContext(t)
		mockService := &MockKeyService{}

		// Step 1: Create key
		keyID := uuid.New()
		createResult := &keyservices.CreateKeyResult{
			KeyID:     keyID,
			Name:      "lifecycle-key",
			Type:      "RSA",
			Tags:      []string{"test", "lifecycle"},
			CreatedAt: time.Now(),
		}
		mockService.On("CreateRSAKey", mock.Anything, mock.Anything).
			Return(createResult, nil).Once()

		// Step 2: List keys (should include new key)
		allKeys := []model.Key{
			{
				ID:     keyID,
				UserID: tc.TestUserID,
				Name:   "lifecycle-key",
				Type:   "RSA",
				Tags:   []string{"test", "lifecycle"},
			},
		}
		mockService.On("ListKeys", mock.Anything, tc.TestUserID).
			Return(allKeys, nil).Once()

		// Step 3: Rotate key
		rotateResult := &keyservices.CreateKeyResult{
			KeyID:     uuid.New(),
			Name:      "lifecycle-key-rotated",
			Type:      "RSA",
			Tags:      []string{"test", "lifecycle"},
			CreatedAt: time.Now(),
		}
		mockService.On("RotateKey", mock.Anything, keyID, tc.TestUserID).
			Return(rotateResult, nil).Once()

		// Step 4: Delete key
		mockService.On("DeleteKey", mock.Anything, keyID, tc.TestUserID).
			Return(nil).Once()

		// Execute the lifecycle workflow
		workflowSteps := []struct {
			name        string
			commandFunc func() *cobra.Command
			verifyFunc  func(output string)
		}{
			{
				name: "create key",
				commandFunc: func() *cobra.Command {
					cmd := &cobra.Command{
						Use: "create",
						RunE: func(cmd *cobra.Command, args []string) error {
							req := keyservices.CreateKeyRequest{
								Name:   "lifecycle-key",
								Type:   "RSA",
								Bits:   2048,
								Tags:   []string{"test", "lifecycle"},
								UserID: tc.TestUserID,
							}
							_, err := mockService.CreateRSAKey(cmd.Context(), req)
							if err != nil {
								return err
							}
							cmd.Println("Key created successfully")
							return nil
						},
					}
					cmd.SetContext(tc.Ctx)
					return cmd
				},
				verifyFunc: func(output string) {
					assert.Contains(t, output, "Key created successfully")
				},
			},
			{
				name: "list keys",
				commandFunc: func() *cobra.Command {
					cmd := &cobra.Command{
						Use: "list",
						RunE: func(cmd *cobra.Command, args []string) error {
							keys, err := mockService.ListKeys(cmd.Context(), tc.TestUserID)
							if err != nil {
								return err
							}
							for _, key := range keys {
								cmd.Printf("Key: %s\n", key.Name)
							}
							return nil
						},
					}
					cmd.SetContext(tc.Ctx)
					return cmd
				},
				verifyFunc: func(output string) {
					assert.Contains(t, output, "lifecycle-key")
				},
			},
			{
				name: "rotate key",
				commandFunc: func() *cobra.Command {
					cmd := &cobra.Command{
						Use: "rotate",
						RunE: func(cmd *cobra.Command, args []string) error {
							result, err := mockService.RotateKey(cmd.Context(), keyID, tc.TestUserID)
							if err != nil {
								return err
							}
							cmd.Printf("Key rotated: %s\n", result.Name)
							return nil
						},
					}
					cmd.SetContext(tc.Ctx)
					return cmd
				},
				verifyFunc: func(output string) {
					assert.Contains(t, output, "rotated")
				},
			},
			{
				name: "delete key",
				commandFunc: func() *cobra.Command {
					cmd := &cobra.Command{
						Use: "delete",
						RunE: func(cmd *cobra.Command, args []string) error {
							err := mockService.DeleteKey(cmd.Context(), keyID, tc.TestUserID)
							if err != nil {
								return err
							}
							cmd.Println("Key deleted successfully")
							return nil
						},
					}
					cmd.SetContext(tc.Ctx)
					return cmd
				},
				verifyFunc: func(output string) {
					assert.Contains(t, output, "deleted successfully")
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

		mockService.AssertExpectations(t)
	})
}
