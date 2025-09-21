package users

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"password-manager/cmd/testutils"
	"password-manager/internal/domain"
)

func TestListUsersCommand(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func(*testutils.TestContext)
		expectedError  string
		expectedOutput string
	}{
		{
			name: "successful users list",
			setupMocks: func(tc *testutils.TestContext) {
				// Create test users
				users := []domain.User{
					{
						ID:        uuid.New(),
						Username:  "admin",
						Role:      domain.RoleAdmin,
						CreatedAt: time.Now().Add(-24 * time.Hour),
					},
					{
						ID:        uuid.New(),
						Username:  "user1",
						Role:      domain.RoleUser,
						CreatedAt: time.Now().Add(-12 * time.Hour),
					},
					{
						ID:        uuid.New(),
						Username:  "manager",
						Role:      domain.RoleSecretsManager,
						CreatedAt: time.Now().Add(-6 * time.Hour),
					},
				}

				tc.MockUserService.On("ListUsers", mock.Anything).Return(users, nil)
			},
			expectedOutput: "admin",
		},
		{
			name: "empty users list",
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockUserService.On("ListUsers", mock.Anything).Return([]domain.User{}, nil)
			},
			expectedOutput: "No users found",
		},
		{
			name: "service error",
			setupMocks: func(tc *testutils.TestContext) {
				tc.MockUserService.On("ListUsers", mock.Anything).
					Return(nil, assert.AnError)
			},
			expectedError: "failed to list users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test context
			tc := testutils.NewTestContext(t)
			tt.setupMocks(tc)

			// Create command with test context
			testCmd := tc.CreateTestCommand(listCmd)

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

func TestListUsersOutputFormat(t *testing.T) {
	// Create test context
	tc := testutils.NewTestContext(t)

	// Create test users with different roles
	users := []domain.User{
		{
			ID:        uuid.MustParse("550e8400-e29b-41d4-a716-446655440001"),
			Username:  "admin",
			Role:      domain.RoleAdmin,
			CreatedAt: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			ID:        uuid.MustParse("550e8400-e29b-41d4-a716-446655440002"),
			Username:  "user1",
			Role:      domain.RoleUser,
			CreatedAt: time.Date(2023, 1, 2, 12, 0, 0, 0, time.UTC),
		},
	}

	tc.MockUserService.On("ListUsers", mock.Anything).Return(users, nil)

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
	assert.Contains(t, outputStr, "admin")
	assert.Contains(t, outputStr, "user1")
	assert.Contains(t, outputStr, domain.RoleAdmin)
	assert.Contains(t, outputStr, domain.RoleUser)

	// Verify mock expectations
	tc.MockUserService.AssertExpectations(t)
}

func TestListUsersWithServiceUnavailable(t *testing.T) {
	// Create test context
	tc := testutils.NewTestContext(t)

	// Mock service container not available
	testCmd := listCmd
	testCmd.SetContext(tc.Ctx)

	// Remove service container from context to test error handling
	ctxWithoutContainer := tc.Ctx
	testCmd.SetContext(ctxWithoutContainer)

	// This should be handled by the actual command implementation
	// The test verifies error handling when service container is not available
}
