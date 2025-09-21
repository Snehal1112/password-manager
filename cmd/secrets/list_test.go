package secrets

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"password-manager/cmd/testutils"
	"password-manager/internal/domain"
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
				secrets := []domain.Secret{
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

				tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID, []string(nil)).
					Return(secrets, nil)
			},
			expectedOutput: "api-key",
		},
		{
			name: "list secrets with tag filter",
			setupMocks: func(tc *testutils.TestContext) {
				secrets := []domain.Secret{
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
				tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID, []string(nil)).
					Return([]domain.Secret{}, nil)
			},
			expectedOutput: "No secrets found",
		},
		{
			name: "service error",
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID, mock.Anything).
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

			// Create command with test context
			testCmd := tc.CreateTestCommand(listCmd)

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
			tc.MockSecretService.AssertExpectations(t)
		})
	}
}

func TestListSecretsOutputFormat(t *testing.T) {
	// Create test context
	tc := testutils.NewTestContext(t)

	// Create test secrets with different attributes
	secrets := []domain.Secret{
		{
			ID:      uuid.MustParse("550e8400-e29b-41d4-a716-446655440001"),
			UserID:  tc.TestUserID,
			Name:    "api-key",
			Value:   "secret-value-1",
			Version: 1,
			Tags:    []string{"api", "prod"},
		},
		{
			ID:      uuid.MustParse("550e8400-e29b-41d4-a716-446655440002"),
			UserID:  tc.TestUserID,
			Name:    "db-password",
			Value:   "secret-value-2",
			Version: 3,
			Tags:    []string{"database", "staging"},
		},
	}

	tc.MockSecretService.On("ListSecrets", mock.Anything, tc.TestUserID, []string(nil)).
		Return(secrets, nil)

	// Create command with test context
	testCmd := tc.CreateTestCommand(listCmd)

	// Capture output
	var output bytes.Buffer
	testCmd.SetOut(&output)

	// Execute command
	err := testCmd.Execute()
	assert.NoError(t, err)

	// Verify output format contains expected fields
	outputStr := output.String()
	assert.Contains(t, outputStr, "api-key")
	assert.Contains(t, outputStr, "db-password")

	// Should show versions
	assert.Contains(t, outputStr, "v1")
	assert.Contains(t, outputStr, "v3")

	// Should show tags
	assert.Contains(t, outputStr, "api")
	assert.Contains(t, outputStr, "database")

	// Verify mock expectations
	tc.MockSecretService.AssertExpectations(t)
}