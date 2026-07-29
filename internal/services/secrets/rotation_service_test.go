package secrets_test

import (
	"context"
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
func (m *mockRotationPolicyRepo) Read(ctx context.Context, id uuid.UUID) (*model.RotationPolicy, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.RotationPolicy), args.Error(1)
}
func (m *mockRotationPolicyRepo) Update(ctx context.Context, policy *model.RotationPolicy) error {
	return m.Called(ctx, policy).Error(0)
}
func (m *mockRotationPolicyRepo) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}
func (m *mockRotationPolicyRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]model.RotationPolicy, error) {
	args := m.Called(ctx, userID)
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
func (m *mockRotationPolicyRepo) GetDueRotations(ctx context.Context, userID uuid.UUID) ([]model.SecretPolicy, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.SecretPolicy), args.Error(1)
}
func (m *mockRotationPolicyRepo) GetUpcomingReminders(ctx context.Context, userID uuid.UUID) ([]model.RotationReminder, error) {
	args := m.Called(ctx, userID)
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

func TestGetSecretPolicies_NonOwner_Forbidden(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New()
	secretID := uuid.New()

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID, model.NewAdminScope(callerID)).Return(&model.Secret{ID: secretID, UserID: ownerID}, nil)
	rotationRepo := &mockRotationPolicyRepo{}

	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, testutils.NewTestLogger(t))
	_, err := svc.GetSecretPolicies(ctx, secretID, callerID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not own")
	rotationRepo.AssertNotCalled(t, "GetPoliciesForSecret", mock.Anything, mock.Anything)
}

func TestGetSecretPolicies_Owner_Succeeds(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerID := uuid.New()
	secretID := uuid.New()

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID, model.NewAdminScope(ownerID)).Return(&model.Secret{ID: secretID, UserID: ownerID}, nil)
	rotationRepo := &mockRotationPolicyRepo{}
	rotationRepo.On("GetPoliciesForSecret", ctx, secretID).Return([]model.RotationPolicy{{ID: uuid.New()}}, nil)

	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, testutils.NewTestLogger(t))
	policies, err := svc.GetSecretPolicies(ctx, secretID, ownerID)

	require.NoError(t, err)
	assert.Len(t, policies, 1)
}

func TestGetSecretPolicies_NilUserID_SkipsOwnershipCheck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()

	secretRepo := &testutils.MockSecretRepository{}
	rotationRepo := &mockRotationPolicyRepo{}
	rotationRepo.On("GetPoliciesForSecret", ctx, secretID).Return([]model.RotationPolicy{}, nil)

	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, testutils.NewTestLogger(t))
	_, err := svc.GetSecretPolicies(ctx, secretID, uuid.Nil)

	require.NoError(t, err)
	secretRepo.AssertNotCalled(t, "Read", mock.Anything, mock.Anything)
}

func TestAcknowledgeReminder_NonOwner_Forbidden(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ownerID := uuid.New()
	callerID := uuid.New()
	secretID := uuid.New()
	reminderID := uuid.New()

	secretRepo := &testutils.MockSecretRepository{}
	secretRepo.On("Read", ctx, secretID, model.NewAdminScope(callerID)).Return(&model.Secret{ID: secretID, UserID: ownerID}, nil)
	rotationRepo := &mockRotationPolicyRepo{}

	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, testutils.NewTestLogger(t))
	err := svc.AcknowledgeReminder(ctx, reminderID, secretID, callerID)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not own")
	rotationRepo.AssertNotCalled(t, "UpdateReminder", mock.Anything, mock.Anything)
}

func TestAcknowledgeReminder_SystemCaller_SkipsOwnershipCheck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	secretID := uuid.New()
	reminderID := uuid.New()

	secretRepo := &testutils.MockSecretRepository{}
	rotationRepo := &mockRotationPolicyRepo{}
	rotationRepo.On("UpdateReminder", ctx, mock.MatchedBy(func(r *model.RotationReminder) bool {
		return r.ID == reminderID && r.Acknowledged
	})).Return(nil)

	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, testutils.NewTestLogger(t))
	err := svc.AcknowledgeReminder(ctx, reminderID, secretID, uuid.Nil)

	require.NoError(t, err)
	secretRepo.AssertNotCalled(t, "Read", mock.Anything, mock.Anything)
	rotationRepo.AssertExpectations(t)
}
