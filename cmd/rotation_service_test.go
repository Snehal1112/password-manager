package cmd

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/cmd/testutils"
	"rocketvault/internal/domain"
	secretServices "rocketvault/internal/services/secrets"
)

// MockRotationSvc is a testify mock that satisfies RotationServiceInterface.
type MockRotationSvc struct{ mock.Mock }

func (m *MockRotationSvc) CreatePolicy(ctx context.Context, req secretServices.CreatePolicyRequest) (*domain.RotationPolicy, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.RotationPolicy), args.Error(1)
}

func (m *MockRotationSvc) GetPolicy(ctx context.Context, id uuid.UUID) (*domain.RotationPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.RotationPolicy), args.Error(1)
}

func (m *MockRotationSvc) UpdatePolicy(ctx context.Context, req secretServices.UpdatePolicyRequest) (*domain.RotationPolicy, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.RotationPolicy), args.Error(1)
}

func (m *MockRotationSvc) DeletePolicy(ctx context.Context, id uuid.UUID, callerID uuid.UUID) error {
	args := m.Called(ctx, id, callerID)
	return args.Error(0)
}

func (m *MockRotationSvc) ListUserPolicies(ctx context.Context, userID uuid.UUID) ([]domain.RotationPolicy, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.RotationPolicy), args.Error(1)
}

func (m *MockRotationSvc) AssignPolicyToSecret(ctx context.Context, req secretServices.AssignPolicyRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockRotationSvc) RemovePolicyFromSecret(ctx context.Context, sID, pID uuid.UUID, callerID uuid.UUID) error {
	args := m.Called(ctx, sID, pID, callerID)
	return args.Error(0)
}

func (m *MockRotationSvc) GetSecretPolicies(ctx context.Context, secretID uuid.UUID) ([]domain.RotationPolicy, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.RotationPolicy), args.Error(1)
}

func (m *MockRotationSvc) PerformManualRotation(ctx context.Context, req secretServices.ManualRotationRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockRotationSvc) GetRotationHistory(ctx context.Context, sID uuid.UUID, callerID uuid.UUID) ([]domain.RotationHistory, error) {
	args := m.Called(ctx, sID, callerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.RotationHistory), args.Error(1)
}

func (m *MockRotationSvc) GetDueRotations(ctx context.Context, userID uuid.UUID) ([]domain.SecretPolicy, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.SecretPolicy), args.Error(1)
}

func (m *MockRotationSvc) CreateRotationReminder(ctx context.Context, req secretServices.CreateReminderRequest) error {
	return nil
}

func (m *MockRotationSvc) GetUpcomingReminders(ctx context.Context, userID uuid.UUID) ([]domain.RotationReminder, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.RotationReminder), args.Error(1)
}

func (m *MockRotationSvc) AcknowledgeReminder(ctx context.Context, reminderID uuid.UUID) error {
	return nil
}

func setupRotationTestContext(t *testing.T) (*testutils.TestContext, *MockRotationSvc) {
	tc := testutils.NewTestContext(t)
	mockRotSvc := &MockRotationSvc{}
	tc.MockContainer.On("GetRotationService").Return(mockRotSvc)
	return tc, mockRotSvc
}

func TestRotationCreateCommand_UsesService(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	polID := uuid.New()

	mockRotSvc.On("CreatePolicy", mock.Anything, mock.MatchedBy(func(r secretServices.CreatePolicyRequest) bool {
		return r.Name == "test-policy" && r.IntervalDays == 30 && r.UserID == tc.TestUserID
	})).Return(&domain.RotationPolicy{ID: polID, Name: "test-policy", IntervalDays: 30}, nil)

	policyName = "test-policy"
	policyInterval = 30
	policyReminder = 7
	policyAutoRotate = false
	policyDescription = ""

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "create", RunE: rotationCreateCmd.RunE}
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "created successfully")
	mockRotSvc.AssertExpectations(t)
}

func TestRotationListCommand_UsesService(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)

	mockRotSvc.On("ListUserPolicies", mock.Anything, tc.TestUserID).
		Return([]domain.RotationPolicy{
			{ID: uuid.New(), Name: "policy-1", IntervalDays: 30, AutoRotate: true, Enabled: true, CreatedAt: time.Now()},
		}, nil)

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "list", RunE: rotationListCmd.RunE}
	cmd.SetContext(tc.Ctx)
	cmd.SetOut(&out)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "policy-1")
	mockRotSvc.AssertExpectations(t)
}

func TestRotationRotateCommand_UsesContextContainer(t *testing.T) {
	tc, mockRotSvc := setupRotationTestContext(t)
	sid := uuid.New()
	pid := uuid.New()

	mockRotSvc.On("PerformManualRotation", mock.Anything, mock.MatchedBy(func(r secretServices.ManualRotationRequest) bool {
		return r.SecretID == sid && r.PolicyID == pid && r.UserID == tc.TestUserID
	})).Return(nil)

	secretID = sid.String()
	policyID = pid.String()

	cmd := &cobra.Command{Use: "rotate", RunE: rotationRotateCmd.RunE}
	cmd.SetContext(tc.Ctx)

	err := cmd.RunE(cmd, []string{})
	assert.NoError(t, err)
	mockRotSvc.AssertExpectations(t)
}
