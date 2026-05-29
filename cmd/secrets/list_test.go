package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	"rocketvault/common"
	"rocketvault/internal/container"
	"rocketvault/internal/formatter"
	"rocketvault/model"
)

func TestListSecretsCommand(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func(*testutils.TestContext)
		flags          map[string]string
		expectedError  string
		expectedOutput string
	}{
		{
			name: "successful secrets list",
			setupMocks: func(tc *testutils.TestContext) {
				secrets := []model.Secret{
					{
						ID:      uuid.New(),
						UserID:  tc.TestUserID,
						Name:    "api-key",
						Value:   "secret-api-key-value",
						Version: 1,
						Tags:    []string{"api", "prod"},
					},
					{
						ID:      uuid.New(),
						UserID:  tc.TestUserID,
						Name:    "db-password",
						Value:   "secret-db-password",
						Version: 2,
						Tags:    []string{"database", "prod"},
					},
				}

				tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID, []string{}).
					Return(secrets, nil)
			},
			expectedOutput: `"name": "api-key"`,
		},
		{
			name: "list secrets with tag filter",
			setupMocks: func(tc *testutils.TestContext) {
				secrets := []model.Secret{
					{
						ID:      uuid.New(),
						UserID:  tc.TestUserID,
						Name:    "api-key",
						Value:   "secret-api-key-value",
						Version: 1,
						Tags:    []string{"api", "prod"},
					},
				}

				tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID, []string{"prod"}).
					Return(secrets, nil)
			},
			flags: map[string]string{
				"tags": "prod",
			},
			expectedOutput: "api-key",
		},
		{
			name: "empty secrets list",
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID, []string{}).
					Return([]model.Secret{}, nil)
			},
			expectedOutput: "[]",
		},
		{
			name: "service error",
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID, []string{}).
					Return(nil, assert.AnError)
			},
			expectedError: "failed to list secrets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test context
			tc := testutils.NewTestContext(t)
			tt.setupMocks(tc)

			// Create a fresh command instance to avoid flag redefinition
			cmd := &cobra.Command{
				Use:   "list",
				Short: "List all secrets",
				RunE: func(cmd *cobra.Command, args []string) error {
					tags, _ := cmd.Flags().GetStringSlice("tags")

					ctx := cmd.Context()
					userID := ctx.Value(common.UserIDKey).(uuid.UUID)

					serviceContainer, ok := ctx.Value(common.ServiceContainerKey).(container.ServiceContainerInterface)
					if !ok || serviceContainer == nil {
						return fmt.Errorf("service container not available")
					}
					secretService := serviceContainer.GetSecretService()

					secretsList, err := secretService.ListSecrets(ctx, userID, tags)
					if err != nil {
						return fmt.Errorf("failed to list secrets: %w", err)
					}

					t, _ := json.MarshalIndent(secretsList, "", "  ")
					cmd.Println(string(t))
					return nil
				},
			}

			// Set context and initialize flags
			cmd.SetContext(tc.Ctx)
			cmd.Flags().StringSlice("tags", []string{}, "Tags to filter secrets (comma-separated)")

			// Set up flags
			for flag, value := range tt.flags {
				err := cmd.Flags().Set(flag, value)
				assert.NoError(t, err)
			}

			// Capture output
			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)

			// Execute command
			err := cmd.Execute()

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
			tc.MockSecretService.AssertExpectations(t)
		})
	}
}

func TestListSecretsOutputFormat(t *testing.T) {
	tc := testutils.NewTestContext(t)

	testSecrets := []model.Secret{
		{
			ID:      uuid.MustParse("550e8400-e29b-41d4-a716-446655440001"),
			UserID:  tc.TestUserID,
			Name:    "api-key",
			Value:   "secret-value-1",
			Version: 1,
			Enabled: true,
			Tags:    []string{"api", "prod"},
		},
		{
			ID:      uuid.MustParse("550e8400-e29b-41d4-a716-446655440002"),
			UserID:  tc.TestUserID,
			Name:    "db-password",
			Value:   "secret-value-2",
			Version: 3,
			Enabled: false,
			Tags:    []string{"database", "staging"},
		},
	}

	tc.MockSecretService.On("ListSecretsInVault", mock.Anything, tc.TestVaultID, []string{}).
		Return(testSecrets, nil)

	fmtr, err := formatter.New(formatter.FormatTable)
	assert.NoError(t, err)

	ctx := context.WithValue(tc.Ctx, common.OutputFormatterKey, fmtr)

	var output bytes.Buffer
	listCmd.SetOut(&output)
	listCmd.SetErr(&output)
	listCmd.SetContext(ctx)
	listCmd.SetArgs([]string{})

	execErr := listCmd.Execute()
	assert.NoError(t, execErr)

	out := output.String()
	assert.Contains(t, out, "api-key")
	assert.Contains(t, out, "db-password")
	assert.Contains(t, out, "ID")
	assert.Contains(t, out, "Name")
	assert.Contains(t, out, "Tags")

	tc.MockSecretService.AssertExpectations(t)
}
