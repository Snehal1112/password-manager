package cmd

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"rocketvault/model"
	secretServices "rocketvault/internal/services/secrets"
)

type mockRotationService struct {
	mock.Mock
}

func (m *mockRotationService) CreatePolicy(ctx context.Context, req secretServices.CreatePolicyRequest) (*model.RotationPolicy, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) GetPolicy(ctx context.Context, id uuid.UUID) (*model.RotationPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) UpdatePolicy(ctx context.Context, req secretServices.UpdatePolicyRequest) (*model.RotationPolicy, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) DeletePolicy(ctx context.Context, id uuid.UUID, callerID uuid.UUID) error {
	return m.Called(ctx, id, callerID).Error(0)
}

func (m *mockRotationService) ListUserPolicies(ctx context.Context, userID uuid.UUID) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) AssignPolicyToSecret(ctx context.Context, req secretServices.AssignPolicyRequest) error {
	return m.Called(ctx, req).Error(0)
}

func (m *mockRotationService) RemovePolicyFromSecret(ctx context.Context, secretID, policyID uuid.UUID, callerID uuid.UUID) error {
	return m.Called(ctx, secretID, policyID, callerID).Error(0)
}

func (m *mockRotationService) GetSecretPolicies(ctx context.Context, secretID uuid.UUID) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, secretID)
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) PerformManualRotation(ctx context.Context, req secretServices.ManualRotationRequest) error {
	return m.Called(ctx, req).Error(0)
}

func (m *mockRotationService) GetRotationHistory(ctx context.Context, secretID uuid.UUID, callerID uuid.UUID) ([]model.RotationHistory, error) {
	args := m.Called(ctx, secretID, callerID)
	return args.Get(0).([]model.RotationHistory), args.Error(1)
}

func (m *mockRotationService) GetDueRotations(ctx context.Context, userID uuid.UUID) ([]model.SecretPolicy, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]model.SecretPolicy), args.Error(1)
}

func (m *mockRotationService) CreateRotationReminder(ctx context.Context, req secretServices.CreateReminderRequest) error {
	return m.Called(ctx, req).Error(0)
}

func (m *mockRotationService) GetUpcomingReminders(ctx context.Context, userID uuid.UUID) ([]model.RotationReminder, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]model.RotationReminder), args.Error(1)
}

func (m *mockRotationService) AcknowledgeReminder(ctx context.Context, reminderID uuid.UUID) error {
	return m.Called(ctx, reminderID).Error(0)
}

func TestRotationDeletePassesCallerID(t *testing.T) {
	callerID := uuid.New()
	policyUUID := uuid.New()

	svc := &mockRotationService{}
	svc.On("DeletePolicy", mock.Anything, policyUUID, callerID).Return(nil)

	err := svc.DeletePolicy(context.Background(), policyUUID, callerID)
	assert.NoError(t, err)
	svc.AssertCalled(t, "DeletePolicy", mock.Anything, policyUUID, callerID)
}

func TestRotationDeleteOwnershipRejection(t *testing.T) {
	callerID := uuid.New()
	policyUUID := uuid.New()

	svc := &mockRotationService{}
	svc.On("DeletePolicy", mock.Anything, policyUUID, callerID).
		Return(fmt.Errorf("forbidden: user does not own this policy"))

	err := svc.DeletePolicy(context.Background(), policyUUID, callerID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestRotationHistoryPassesCallerID(t *testing.T) {
	callerID := uuid.New()
	secretUUID := uuid.New()

	svc := &mockRotationService{}
	svc.On("GetRotationHistory", mock.Anything, secretUUID, callerID).
		Return([]model.RotationHistory{}, nil)

	history, err := svc.GetRotationHistory(context.Background(), secretUUID, callerID)
	assert.NoError(t, err)
	assert.Empty(t, history)
	svc.AssertCalled(t, "GetRotationHistory", mock.Anything, secretUUID, callerID)
}

func TestRotationHistoryOwnershipRejection(t *testing.T) {
	callerID := uuid.New()
	secretUUID := uuid.New()

	svc := &mockRotationService{}
	svc.On("GetRotationHistory", mock.Anything, secretUUID, callerID).
		Return([]model.RotationHistory(nil), fmt.Errorf("forbidden: user does not own this secret"))

	_, err := svc.GetRotationHistory(context.Background(), secretUUID, callerID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}
