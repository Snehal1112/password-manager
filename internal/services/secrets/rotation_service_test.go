package secrets_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/services/secrets"
	"rocketvault/internal/testutils"
	"rocketvault/model"
)

// mockRotationPolicyRepo is a testify mock of repositories.RotationPolicyRepositoryInterface.
type mockRotationPolicyRepo struct{ mock.Mock }

func (m *mockRotationPolicyRepo) Create(ctx context.Context, policy *model.RotationPolicy) error {
	return m.Called(ctx, policy).Error(0)
}
func (m *mockRotationPolicyRepo) Read(ctx context.Context, id uuid.UUID, scope model.Scope) (*model.RotationPolicy, error) {
	args := m.Called(ctx, id, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}
func (m *mockRotationPolicyRepo) Update(ctx context.Context, policy *model.RotationPolicy, scope model.Scope) error {
	return m.Called(ctx, policy, scope).Error(0)
}
func (m *mockRotationPolicyRepo) Delete(ctx context.Context, id uuid.UUID, scope model.Scope) error {
	return m.Called(ctx, id, scope).Error(0)
}
func (m *mockRotationPolicyRepo) List(ctx context.Context, scope model.Scope) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}
func (m *mockRotationPolicyRepo) AssignToSecret(ctx context.Context, secretID, policyID uuid.UUID, assignedAt, nextRotationAt time.Time) error {
	return m.Called(ctx, secretID, policyID, assignedAt, nextRotationAt).Error(0)
}
func (m *mockRotationPolicyRepo) RemoveFromSecret(ctx context.Context, secretID, policyID uuid.UUID) error {
	return m.Called(ctx, secretID, policyID).Error(0)
}
func (m *mockRotationPolicyRepo) GetSecretPolicies(ctx context.Context, secretID uuid.UUID) ([]model.SecretPolicy, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretPolicy), args.Error(1)
}
func (m *mockRotationPolicyRepo) GetPoliciesForSecret(ctx context.Context, secretID uuid.UUID) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationPolicy), args.Error(1)
}
func (m *mockRotationPolicyRepo) UpdateSecretPolicyRotation(ctx context.Context, secretID, policyID uuid.UUID, lastRotatedAt, nextRotationAt time.Time) error {
	return m.Called(ctx, secretID, policyID, lastRotatedAt, nextRotationAt).Error(0)
}
func (m *mockRotationPolicyRepo) RecordRotation(ctx context.Context, history *model.RotationHistory) error {
	return m.Called(ctx, history).Error(0)
}
func (m *mockRotationPolicyRepo) GetRotationHistory(ctx context.Context, secretID uuid.UUID) ([]model.RotationHistory, error) {
	args := m.Called(ctx, secretID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationHistory), args.Error(1)
}
func (m *mockRotationPolicyRepo) GetDueRotations(ctx context.Context, scope model.Scope) ([]model.SecretPolicy, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretPolicy), args.Error(1)
}
func (m *mockRotationPolicyRepo) GetUpcomingReminders(ctx context.Context, scope model.Scope) ([]model.RotationReminder, error) {
	args := m.Called(ctx, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.RotationReminder), args.Error(1)
}
func (m *mockRotationPolicyRepo) CreateReminder(ctx context.Context, reminder *model.RotationReminder) error {
	return m.Called(ctx, reminder).Error(0)
}
func (m *mockRotationPolicyRepo) UpdateReminder(ctx context.Context, reminder *model.RotationReminder) error {
	return m.Called(ctx, reminder).Error(0)
}
func (m *mockRotationPolicyRepo) GetReminderBySecret(ctx context.Context, secretID, policyID uuid.UUID, reminderType string) (*model.RotationReminder, error) {
	args := m.Called(ctx, secretID, policyID, reminderType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationReminder), args.Error(1)
}

func TestGetSecretPolicies_OutOfScope_NotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	callerID := uuid.New()
	secretID := uuid.New()
	scope := model.NewOwnerScope(vaultID, callerID)

	secretRepo := &testutils.MockSecretRepository{}
	// A caller-scoped read that doesn't match the secret's real owner/vault
	// fails at the repository the same way a real scoped query would --
	// there's no separate ownership comparison left to run.
	secretRepo.On("Read", ctx, secretID, scope).Return(nil, errors.New("secret not found"))
	rotationRepo := &mockRotationPolicyRepo{}

	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, testutils.NewTestLogger(t), nil)
	_, err := svc.GetSecretPolicies(ctx, secretID, scope)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret not found")
	rotationRepo.AssertNotCalled(t, "GetPoliciesForSecret", mock.Anything, mock.Anything)
}

func TestGetSecretPolicies_InScope_Succeeds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	ownerID := uuid.New()
	secretID := uuid.New()
	scope := model.NewOwnerScope(vaultID, ownerID)

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID, scope).Return(&model.Secret{ID: secretID, UserID: ownerID}, nil)
	rotationRepo := &mockRotationPolicyRepo{}
	rotationRepo.On("GetPoliciesForSecret", ctx, secretID).Return([]model.RotationPolicy{{ID: uuid.New()}}, nil)

	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, testutils.NewTestLogger(t), nil)
	policies, err := svc.GetSecretPolicies(ctx, secretID, scope)

	require.NoError(t, err)
	assert.Len(t, policies, 1)
}

func TestGetSecretPolicies_AdminScope_Succeeds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	scope := model.NewAdminScope(uuid.Nil)

	secretRepo := &testutils.MockSecretRepository{}
	// AdminScope has no predicate, so a system/scheduler caller still reads
	// the secret (there's no uuid.Nil sentinel skipping it anymore) and the
	// read simply always succeeds.
	secretRepo.On("Read", ctx, secretID, scope).Return(&model.Secret{ID: secretID}, nil)
	rotationRepo := &mockRotationPolicyRepo{}
	rotationRepo.On("GetPoliciesForSecret", ctx, secretID).Return([]model.RotationPolicy{}, nil)

	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, testutils.NewTestLogger(t), nil)
	_, err := svc.GetSecretPolicies(ctx, secretID, scope)

	require.NoError(t, err)
	secretRepo.AssertExpectations(t)
}

func TestAcknowledgeReminder_OutOfScope_NotFound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	vaultID := uuid.New()
	callerID := uuid.New()
	secretID := uuid.New()
	reminderID := uuid.New()
	scope := model.NewOwnerScope(vaultID, callerID)

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID, scope).Return(nil, errors.New("secret not found"))
	rotationRepo := &mockRotationPolicyRepo{}

	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, testutils.NewTestLogger(t), nil)
	err := svc.AcknowledgeReminder(ctx, reminderID, secretID, scope)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret not found")
	rotationRepo.AssertNotCalled(t, "UpdateReminder", mock.Anything, mock.Anything)
}

func TestAcknowledgeReminder_AdminScope_Succeeds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	reminderID := uuid.New()
	scope := model.NewAdminScope(uuid.Nil)

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID, scope).Return(&model.Secret{ID: secretID}, nil)
	rotationRepo := &mockRotationPolicyRepo{}
	rotationRepo.On("UpdateReminder", ctx, mock.MatchedBy(func(r *model.RotationReminder) bool {
		return r.ID == reminderID && r.Acknowledged
	})).Return(nil)

	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, testutils.NewTestLogger(t), nil)
	err := svc.AcknowledgeReminder(ctx, reminderID, secretID, scope)

	require.NoError(t, err)
	secretRepo.AssertExpectations(t)
	rotationRepo.AssertExpectations(t)
}
