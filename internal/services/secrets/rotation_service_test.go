package secrets_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/repositories"
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

// setupAssignmentDB builds a real in-memory SQLite database with the secrets,
// rotation_policies and secret_policies tables AssignPolicyToSecret touches.
// The column lists mirror internal/db/db.go's createOptimizedSchema (only the
// columns SecretRepository and RotationPolicyRepository actually read/write).
func setupAssignmentDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck,gosec

	_, err = conn.Exec(`
		CREATE TABLE secrets (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			vault_id TEXT NOT NULL,
			value TEXT NOT NULL,
			version INTEGER NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			deleted_at TIMESTAMP NULL,
			purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
			content_type TEXT NOT NULL DEFAULT '',
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			expires_at TIMESTAMP NULL,
			not_before TIMESTAMP NULL
		);
		CREATE TABLE rotation_policies (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			vault_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			interval_days INTEGER NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			reminder_days INTEGER NOT NULL DEFAULT 7,
			auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE secret_policies (
			secret_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_rotated_at TIMESTAMP,
			next_rotation_at TIMESTAMP,
			PRIMARY KEY (secret_id, policy_id)
		);
		CREATE TABLE rotation_reminders (
			id TEXT PRIMARY KEY,
			secret_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			reminder_type TEXT NOT NULL,
			sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			next_reminder_at TIMESTAMP,
			acknowledged BOOLEAN NOT NULL DEFAULT FALSE
		);
	`)
	require.NoError(t, err)
	return conn
}

// seedSecretInVault inserts one secret directly, bypassing the service layer:
// these tests are about the assignment path, not secret creation.
func seedSecretInVault(t *testing.T, conn *sql.DB, secretID, ownerID, vaultID uuid.UUID) {
	t.Helper()
	_, err := conn.Exec(
		`INSERT INTO secrets (id, user_id, name, vault_id, value, version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		secretID.String(), ownerID.String(), "api-key", vaultID.String(), "ciphertext", 1, time.Now(),
	)
	require.NoError(t, err)
}

// TestAssignPolicyToSecret_CrossVaultDenied_RealRepos is the end-to-end proof
// of this branch's one deviation from its design spec: instead of a separate
// ErrPolicyVaultMismatch comparison, AssignPolicyToSecret reads the secret and
// the policy under the *same* req.Scope, so a policy in another vault fails its
// own scoped read before any comparison would run. Mocked repositories cannot
// prove that -- they return whatever they are told -- so this test wires the
// real SecretRepository and RotationPolicyRepository over SQLite and asserts
// the denial comes from the actual scope predicate.
func TestAssignPolicyToSecret_CrossVaultDenied_RealRepos(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn := setupAssignmentDB(t)
	log := testutils.NewTestLogger(t)

	secretRepo := repositories.NewSecretRepository(rvdb.NewConn(conn, rvdb.SQLite), log)
	rotationRepo := repositories.NewRotationPolicyRepository(rvdb.NewConn(conn, rvdb.SQLite), log)
	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, log, nil)

	vaultA, vaultB := uuid.New(), uuid.New()
	actorID, ownerID := uuid.New(), uuid.New()
	secretID := uuid.New()
	seedSecretInVault(t, conn, secretID, ownerID, vaultA)

	now := time.Now()
	policyInB := &model.RotationPolicy{
		ID: uuid.New(), UserID: ownerID, VaultID: vaultB,
		Name: "vault-b-policy", IntervalDays: 30, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, rotationRepo.Create(ctx, policyInB))

	scopeA := model.NewVaultScope(vaultA, actorID)
	err := svc.AssignPolicyToSecret(ctx, secrets.AssignPolicyRequest{
		SecretID: secretID,
		PolicyID: policyInB.ID,
		Scope:    scopeA,
	})
	require.Error(t, err, "a vault-B policy must not be assignable to a vault-A secret")
	assert.Contains(t, err.Error(), "policy not found")

	// Nothing was written: the denial happens before the join-table insert.
	var assignments int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM secret_policies`).Scan(&assignments))
	assert.Equal(t, 0, assignments, "a denied assignment must not create a secret_policies row")

	// Positive control: the same call succeeds once the policy is in vault A,
	// proving the failure above is the vault predicate and not a broken fixture.
	policyInA := &model.RotationPolicy{
		ID: uuid.New(), UserID: ownerID, VaultID: vaultA,
		Name: "vault-a-policy", IntervalDays: 30, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, rotationRepo.Create(ctx, policyInA))
	require.NoError(t, svc.AssignPolicyToSecret(ctx, secrets.AssignPolicyRequest{
		SecretID: secretID,
		PolicyID: policyInA.ID,
		Scope:    scopeA,
	}))

	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM secret_policies`).Scan(&assignments))
	assert.Equal(t, 1, assignments)
}

// TestAssignPolicyToSecret_CrossVaultSecretDenied_RealRepos is the mirror case:
// the policy is reachable but the secret is not, so the first scoped read is
// what refuses. Together the two tests pin both halves of the shared-scope
// dual read.
func TestAssignPolicyToSecret_CrossVaultSecretDenied_RealRepos(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	conn := setupAssignmentDB(t)
	log := testutils.NewTestLogger(t)

	secretRepo := repositories.NewSecretRepository(rvdb.NewConn(conn, rvdb.SQLite), log)
	rotationRepo := repositories.NewRotationPolicyRepository(rvdb.NewConn(conn, rvdb.SQLite), log)
	svc := secrets.NewRotationService(rotationRepo, secretRepo, nil, nil, log, nil)

	vaultA, vaultB := uuid.New(), uuid.New()
	actorID, ownerID := uuid.New(), uuid.New()
	secretID := uuid.New()
	seedSecretInVault(t, conn, secretID, ownerID, vaultB)

	now := time.Now()
	policyInA := &model.RotationPolicy{
		ID: uuid.New(), UserID: ownerID, VaultID: vaultA,
		Name: "vault-a-policy", IntervalDays: 30, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, rotationRepo.Create(ctx, policyInA))

	err := svc.AssignPolicyToSecret(ctx, secrets.AssignPolicyRequest{
		SecretID: secretID,
		PolicyID: policyInA.ID,
		Scope:    model.NewVaultScope(vaultA, actorID),
	})
	require.Error(t, err, "a vault-B secret must not be assignable from vault A's scope")
	assert.Contains(t, err.Error(), "secret not found")

	var assignments int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM secret_policies`).Scan(&assignments))
	assert.Equal(t, 0, assignments)
}
