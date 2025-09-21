package cmd

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"password-manager/cmd/testutils"
	"password-manager/internal/domain"
	secretServices "password-manager/internal/services/secrets"
)

func TestRotationCreateCommand(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func(*testutils.TestContext)
		flags          map[string]string
		expectedError  string
		expectedOutput string
	}{
		{
			name: "successful rotation policy creation",
			setupMocks: func(tc *testutils.TestContext) {
				expectedPolicy := &domain.RotationPolicy{
					ID:           uuid.New(),
					UserID:       tc.TestUserID,
					Name:         "Monthly Rotation",
					Description:  "Rotate every 30 days",
					IntervalDays: 30,
					ReminderDays: 5,
					CreatedAt:    time.Now(),
				}

				// Mock the rotation service (need to add this to test utils)
				mockRotationService := &MockRotationService{}
				tc.MockContainer.On("GetRotationService").Return(mockRotationService)

				mockRotationService.On("CreatePolicy", mock.Anything, secretServices.CreatePolicyRequest{
					UserID:       tc.TestUserID,
					Name:         "Monthly Rotation",
					Description:  "Rotate every 30 days",
					IntervalDays: 30,
					ReminderDays: 5,
				}).Return(expectedPolicy, nil)
			},
			flags: map[string]string{
				"name":        "Monthly Rotation",
				"description": "Rotate every 30 days",
				"interval":    "30",
				"reminder":    "5",
			},
			expectedOutput: "✅ Rotation policy created successfully",
		},
		{
			name: "missing required name flag",
			setupMocks: func(tc *testutils.TestContext) {
				// No mocks needed for validation error
			},
			flags: map[string]string{
				"interval": "30",
			},
			expectedError: "policy name is required",
		},
		{
			name: "invalid interval",
			setupMocks: func(tc *testutils.TestContext) {
				// No mocks needed for validation error
			},
			flags: map[string]string{
				"name":     "Test Policy",
				"interval": "0",
			},
			expectedError: "interval must be greater than 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test context
			tc := testutils.NewTestContext(t)
			tt.setupMocks(tc)

			// Create command with test context
			testCmd := tc.CreateTestCommand(rotationCreateCmd)

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
			tc.MockContainer.AssertExpectations(t)
		})
	}
}

// Mock Rotation Service for testing
type MockRotationService struct {
	mock.Mock
}

func (m *MockRotationService) CreatePolicy(ctx interface{}, req secretServices.CreatePolicyRequest) (*domain.RotationPolicy, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.RotationPolicy), args.Error(1)
}

func (m *MockRotationService) UpdatePolicy(ctx interface{}, req secretServices.UpdatePolicyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockRotationService) GetPolicy(ctx interface{}, policyID, userID uuid.UUID) (*domain.RotationPolicy, error) {
	args := m.Called(ctx, policyID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.RotationPolicy), args.Error(1)
}

func (m *MockRotationService) ListPolicies(ctx interface{}, userID uuid.UUID) ([]domain.RotationPolicy, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.RotationPolicy), args.Error(1)
}

func (m *MockRotationService) DeletePolicy(ctx interface{}, policyID, userID uuid.UUID) error {
	args := m.Called(ctx, policyID, userID)
	return args.Error(0)
}

func (m *MockRotationService) AssignToSecret(ctx interface{}, req secretServices.AssignPolicyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockRotationService) RemoveFromSecret(ctx interface{}, secretID, policyID, userID uuid.UUID) error {
	args := m.Called(ctx, secretID, policyID, userID)
	return args.Error(0)
}

func (m *MockRotationService) PerformManualRotation(ctx interface{}, req secretServices.ManualRotationRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockRotationService) GetRotationHistory(ctx interface{}, secretID, userID uuid.UUID) ([]domain.RotationHistory, error) {
	args := m.Called(ctx, secretID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.RotationHistory), args.Error(1)
}

func (m *MockRotationService) GetDueRotations(ctx interface{}, userID uuid.UUID) ([]domain.SecretPolicy, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.SecretPolicy), args.Error(1)
}

func (m *MockRotationService) GetUpcomingReminders(ctx interface{}, userID uuid.UUID) ([]domain.RotationReminder, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.RotationReminder), args.Error(1)
}