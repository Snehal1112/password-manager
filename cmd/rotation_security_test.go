package cmd

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	secretServices "rocketvault/internal/services/secrets"
	"rocketvault/model"
)

// mockRotationService implements secretServices.RotationServiceInterface in
// full to verify Task 6's scope-based signatures are threaded through
// correctly by callers of the interface.
type mockRotationService struct {
	mock.Mock
}

var _ secretServices.RotationServiceInterface = (*mockRotationService)(nil)

func (m *mockRotationService) CreatePolicy(ctx context.Context, req secretServices.CreatePolicyRequest) (*model.RotationPolicy, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) GetPolicy(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.RotationPolicy, error) {
	args := m.Called(ctx, id, scope)
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

func (m *mockRotationService) DeletePolicy(ctx context.Context, id uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, id, scope).Error(0)
}

func (m *mockRotationService) ListPolicies(ctx context.Context, scope model.Scope) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, scope)
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) AssignPolicyToSecret(ctx context.Context, req secretServices.AssignPolicyRequest) error {
	return m.Called(ctx, req).Error(0)
}

func (m *mockRotationService) RemovePolicyFromSecret(ctx context.Context, secretID, policyID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, secretID, policyID, scope).Error(0)
}

func (m *mockRotationService) GetSecretPolicies(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, secretID, scope)
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}

func (m *mockRotationService) PerformManualRotation(ctx context.Context, req secretServices.ManualRotationRequest) error {
	return m.Called(ctx, req).Error(0)
}

func (m *mockRotationService) GetRotationHistory(ctx context.Context, secretID uuid.UUID, scope model.Scope) ([]model.RotationHistory, error) {
	args := m.Called(ctx, secretID, scope)
	return args.Get(0).([]model.RotationHistory), args.Error(1)
}

func (m *mockRotationService) GetDueRotations(ctx context.Context, scope model.Scope) ([]model.SecretPolicy, error) {
	args := m.Called(ctx, scope)
	return args.Get(0).([]model.SecretPolicy), args.Error(1)
}

func (m *mockRotationService) CreateRotationReminder(ctx context.Context, req secretServices.CreateReminderRequest) error {
	return m.Called(ctx, req).Error(0)
}

func (m *mockRotationService) GetUpcomingReminders(ctx context.Context, scope model.Scope) ([]model.RotationReminder, error) {
	args := m.Called(ctx, scope)
	return args.Get(0).([]model.RotationReminder), args.Error(1)
}

func (m *mockRotationService) AcknowledgeReminder(ctx context.Context, reminderID, secretID uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, reminderID, secretID, scope).Error(0)
}

func TestRotationDeletePassesCallerID(t *testing.T) {
	callerID := uuid.New()
	vaultID := uuid.New()
	policyUUID := uuid.New()
	scope := model.NewVaultScope(vaultID, callerID)

	svc := &mockRotationService{}
	svc.On("DeletePolicy", mock.Anything, policyUUID, scope).Return(nil)

	err := svc.DeletePolicy(context.Background(), policyUUID, scope)
	assert.NoError(t, err)
	svc.AssertCalled(t, "DeletePolicy", mock.Anything, policyUUID, scope)
}

func TestRotationDeleteOwnershipRejection(t *testing.T) {
	callerID := uuid.New()
	vaultID := uuid.New()
	policyUUID := uuid.New()
	scope := model.NewVaultScope(vaultID, callerID)

	svc := &mockRotationService{}
	svc.On("DeletePolicy", mock.Anything, policyUUID, scope).
		Return(fmt.Errorf("forbidden: user does not own this policy"))

	err := svc.DeletePolicy(context.Background(), policyUUID, scope)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestRotationHistoryPassesCallerID(t *testing.T) {
	callerID := uuid.New()
	vaultID := uuid.New()
	secretUUID := uuid.New()
	scope := model.NewVaultScope(vaultID, callerID)

	svc := &mockRotationService{}
	svc.On("GetRotationHistory", mock.Anything, secretUUID, scope).
		Return([]model.RotationHistory{}, nil)

	history, err := svc.GetRotationHistory(context.Background(), secretUUID, scope)
	assert.NoError(t, err)
	assert.Empty(t, history)
	svc.AssertCalled(t, "GetRotationHistory", mock.Anything, secretUUID, scope)
}

func TestRotationHistoryOwnershipRejection(t *testing.T) {
	callerID := uuid.New()
	vaultID := uuid.New()
	secretUUID := uuid.New()
	scope := model.NewVaultScope(vaultID, callerID)

	svc := &mockRotationService{}
	svc.On("GetRotationHistory", mock.Anything, secretUUID, scope).
		Return([]model.RotationHistory(nil), fmt.Errorf("forbidden: user does not own this secret"))

	_, err := svc.GetRotationHistory(context.Background(), secretUUID, scope)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}
