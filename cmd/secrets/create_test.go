package secrets

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"password-manager/cmd/testutils"
	"password-manager/internal/domain"
	secretServices "password-manager/internal/services/secrets"
)

func TestCreateSecretCommand(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func(*testutils.TestContext)
		flags          map[string]string
		expectedError  string
		expectedOutput string
	}{
		{
			name: "successful secret creation",
			setupMocks: func(tc *testutils.TestContext) {
				expectedSecret := &domain.Secret{
					ID:      uuid.New(),
					UserID:  tc.TestUserID,
					Name:    "test-secret",
					Value:   "secret-value",
					Version: 1,
					Tags:    []string{"test"},
				}
				tc.MockSecretService.On("CreateSecret", mock.Anything, secretServices.CreateSecretRequest{
					UserID: tc.TestUserID,
					Name:   "test-secret",
					Value:  "secret-value",
					Tags:   []string{"test"},
				}).Return(expectedSecret, nil)
			},
			flags: map[string]string{
				"name":  "test-secret",
				"value": "secret-value",
				"tags":  "test",
			},
			expectedOutput: "✅ Secret created successfully",
		},
		{
			name: "missing required name flag",
			setupMocks: func(tc *testutils.TestContext) {
				// No mocks needed for validation error
			},
			flags: map[string]string{
				"value": "secret-value",
			},
			expectedError: "secret name is required",
		},
		{
			name: "missing required value flag",
			setupMocks: func(tc *testutils.TestContext) {
				// No mocks needed for validation error
			},
			flags: map[string]string{
				"name": "test-secret",
			},
			expectedError: "secret value is required",
		},
		{
			name: "service error",
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockSecretService.On("CreateSecret", mock.Anything, mock.Anything).
					Return(nil, assert.AnError)
			},
			flags: map[string]string{
				"name":  "test-secret",
				"value": "secret-value",
			},
			expectedError: "failed to create secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			tc.MockSecretService.AssertExpectations(t)
		})
	}
}

func TestCreateSecretWithTags(t *testing.T) {
	// Create test context
	tc := testutils.NewTestContext(t)

	// Mock successful secret creation with multiple tags
	expectedSecret := &domain.Secret{
		ID:      uuid.New(),
		UserID:  tc.TestUserID,
		Name:    "test-secret",
		Value:   "secret-value",
		Version: 1,
		Tags:    []string{"env:prod", "team:backend", "type:api-key"},
	}

	tc.MockSecretService.On("CreateSecret", mock.Anything, mock.MatchedBy(func(req secretServices.CreateSecretRequest) bool {
		// Check that tags are properly parsed
		return len(req.Tags) == 3 &&
			req.Tags[0] == "env:prod" &&
			req.Tags[1] == "team:backend" &&
			req.Tags[2] == "type:api-key"
	})).Return(expectedSecret, nil)

	// Create command with test context
	testCmd := tc.CreateTestCommand(createCmd)

	// Set up flags with comma-separated tags
	err := testCmd.Flags().Set("name", "test-secret")
	assert.NoError(t, err)
	err = testCmd.Flags().Set("value", "secret-value")
	assert.NoError(t, err)
	err = testCmd.Flags().Set("tags", "env:prod,team:backend,type:api-key")
	assert.NoError(t, err)

	// Execute command
	err = testCmd.Execute()
	assert.NoError(t, err)

	// Verify mock expectations
	tc.MockSecretService.AssertExpectations(t)
}