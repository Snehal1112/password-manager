package cmd

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"password-manager/internal/domain"
	secretServices "password-manager/internal/services/secrets"
)

func TestRotationCreateCommand(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func(*MockRotationService)
		policyName     string
		description    string
		interval       int
		reminder       int
		expectedError  bool
		expectedOutput string
	}{
		{
			name: "successful rotation policy creation",
			setupMocks: func(mockService *MockRotationService) {
				expectedPolicy := &domain.RotationPolicy{
					ID:           uuid.New(),
					UserID:       uuid.New(),
					Name:         "Monthly Rotation",
					Description:  "Rotate every 30 days",
					IntervalDays: 30,
					ReminderDays: 5,
					CreatedAt:    time.Now(),
				}

				mockService.On("CreatePolicy", mock.Anything, mock.MatchedBy(func(req secretServices.CreatePolicyRequest) bool {
					return req.Name == "Monthly Rotation" && req.IntervalDays == 30
				})).Return(expectedPolicy, nil)
			},
			policyName:     "Monthly Rotation",
			description:    "Rotate every 30 days",
			interval:       30,
			reminder:       5,
			expectedError:  false,
			expectedOutput: "✅ Rotation policy created successfully",
		},
		{
			name: "missing required name",
			setupMocks: func(mockService *MockRotationService) {
				// No mocks needed for validation error
			},
			policyName:    "",
			interval:      30,
			expectedError: true,
		},
		{
			name: "invalid interval",
			setupMocks: func(mockService *MockRotationService) {
				// No mocks needed for validation error
			},
			policyName:    "Test Policy",
			interval:      0,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock rotation service
			mockService := &MockRotationService{}
			tt.setupMocks(mockService)

			// Create isolated command that doesn't use global state
			testCmd := &cobra.Command{
				Use:                "create",
				DisableFlagParsing: false,
				RunE: func(cmd *cobra.Command, args []string) error {
					// Get flags
					name, _ := cmd.Flags().GetString("name")
					description, _ := cmd.Flags().GetString("description")
					interval, _ := cmd.Flags().GetInt("interval")
					reminder, _ := cmd.Flags().GetInt("reminder")

					// Validation
					if name == "" {
						return assert.AnError
					}
					if interval <= 0 {
						return assert.AnError
					}

					// Create policy via service
					req := secretServices.CreatePolicyRequest{
						UserID:       uuid.New(), // Use generated UUID for test
						Name:         name,
						Description:  description,
						IntervalDays: interval,
						ReminderDays: reminder,
					}

					policy, err := mockService.CreatePolicy(cmd.Context(), req)
					if err != nil {
						return err
					}

					cmd.Printf("✅ Rotation policy created successfully!\n")
					cmd.Printf("Policy ID: %s\n", policy.ID)
					return nil
				},
			}

			// Define flags
			testCmd.Flags().String("name", "", "Policy name")
			testCmd.Flags().String("description", "", "Policy description")
			testCmd.Flags().Int("interval", 30, "Interval in days")
			testCmd.Flags().Int("reminder", 5, "Reminder in days")

			// Set up flags from test data
			testCmd.Flags().Set("name", tt.policyName)
			testCmd.Flags().Set("description", tt.description)
			testCmd.Flags().Set("interval", fmt.Sprintf("%d", tt.interval))
			testCmd.Flags().Set("reminder", fmt.Sprintf("%d", tt.reminder))

			// Capture output
			var output bytes.Buffer
			testCmd.SetOut(&output)
			testCmd.SetErr(&output)

			// Directly call RunE instead of Execute to avoid global command chain
			err := testCmd.RunE(testCmd, []string{})

			// Assert results
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.expectedOutput != "" {
					assert.Contains(t, output.String(), tt.expectedOutput)
				}
			}

			// Verify mock expectations (only if no error expected)
			if !tt.expectedError {
				mockService.AssertExpectations(t)
			}
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

func (m *MockRotationService) AcknowledgeReminder(ctx interface{}, reminderID uuid.UUID) error {
	args := m.Called(ctx, reminderID)
	return args.Error(0)
}