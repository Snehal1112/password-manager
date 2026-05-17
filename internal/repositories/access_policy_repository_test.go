package repositories_test

import (
"context"
"database/sql"
"testing"

"github.com/google/uuid"
_ "github.com/mattn/go-sqlite3"
"github.com/stretchr/testify/assert"
"github.com/stretchr/testify/require"

"rocketvault/model"
"rocketvault/internal/repositories"
)

func setupAccessPolicyTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS access_policies (
id             TEXT PRIMARY KEY,
principal_id   TEXT NOT NULL,
principal_type TEXT NOT NULL,
resource_type  TEXT NOT NULL,
operation      TEXT NOT NULL,
effect         TEXT NOT NULL,
created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
	`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestAccessPolicyRepository_CreateAndGet(t *testing.T) {
	t.Parallel()
	db := setupAccessPolicyTestDB(t)
	repo := repositories.NewAccessPolicyRepository(db)
	ctx := context.Background()

	principalID := uuid.New()
	policy := &model.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   principalID,
		PrincipalType: model.PrincipalTypeUser,
		ResourceType:  model.PolicyResourceSecrets,
		Operation:     model.OpGet,
		Effect:        model.PolicyEffectAllow,
	}

	require.NoError(t, repo.Create(ctx, policy))

	got, err := repo.GetByID(ctx, policy.ID)
	require.NoError(t, err)
	assert.Equal(t, policy.ID, got.ID)
	assert.Equal(t, model.PolicyEffectAllow, got.Effect)
	assert.Equal(t, model.PolicyResourceSecrets, got.ResourceType)
}

func TestAccessPolicyRepository_ListByPrincipal(t *testing.T) {
	t.Parallel()
	db := setupAccessPolicyTestDB(t)
	repo := repositories.NewAccessPolicyRepository(db)
	ctx := context.Background()

	principalID := uuid.New()
	otherID := uuid.New()

	p1 := &model.AccessPolicy{
		ID: uuid.New(), PrincipalID: principalID, PrincipalType: model.PrincipalTypeUser,
		ResourceType: model.PolicyResourceSecrets, Operation: model.OpGet, Effect: model.PolicyEffectAllow,
	}
	p2 := &model.AccessPolicy{
		ID: uuid.New(), PrincipalID: principalID, PrincipalType: model.PrincipalTypeUser,
		ResourceType: model.PolicyResourceKeys, Operation: model.OpList, Effect: model.PolicyEffectDeny,
	}
	p3 := &model.AccessPolicy{
		ID: uuid.New(), PrincipalID: otherID, PrincipalType: model.PrincipalTypeUser,
		ResourceType: model.PolicyResourceSecrets, Operation: model.OpList, Effect: model.PolicyEffectAllow,
	}
	require.NoError(t, repo.Create(ctx, p1))
	require.NoError(t, repo.Create(ctx, p2))
	require.NoError(t, repo.Create(ctx, p3))

	results, err := repo.ListByPrincipal(ctx, principalID)
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestAccessPolicyRepository_FindEffects(t *testing.T) {
	t.Parallel()
	db := setupAccessPolicyTestDB(t)
	repo := repositories.NewAccessPolicyRepository(db)
	ctx := context.Background()

	principalID := uuid.New()
	p1 := &model.AccessPolicy{
		ID: uuid.New(), PrincipalID: principalID, PrincipalType: model.PrincipalTypeUser,
		ResourceType: model.PolicyResourceSecrets, Operation: model.OpDelete, Effect: model.PolicyEffectAllow,
	}
	p2 := &model.AccessPolicy{
		ID: uuid.New(), PrincipalID: principalID, PrincipalType: model.PrincipalTypeUser,
		ResourceType: model.PolicyResourceSecrets, Operation: model.OpDelete, Effect: model.PolicyEffectDeny,
	}
	require.NoError(t, repo.Create(ctx, p1))
	require.NoError(t, repo.Create(ctx, p2))

	effects, err := repo.FindEffects(ctx, principalID, model.PolicyResourceSecrets, model.OpDelete)
	require.NoError(t, err)
	assert.Len(t, effects, 2)

	hasDeny := false
	for _, e := range effects {
		if e.Effect == model.PolicyEffectDeny {
			hasDeny = true
		}
	}
	assert.True(t, hasDeny)
}

func TestAccessPolicyRepository_Delete(t *testing.T) {
	t.Parallel()
	db := setupAccessPolicyTestDB(t)
	repo := repositories.NewAccessPolicyRepository(db)
	ctx := context.Background()

	policy := &model.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		ResourceType:  model.PolicyResourceCertificates,
		Operation:     model.OpGet,
		Effect:        model.PolicyEffectAllow,
	}
	require.NoError(t, repo.Create(ctx, policy))
	require.NoError(t, repo.Delete(ctx, policy.ID))

	_, err := repo.GetByID(ctx, policy.ID)
	assert.Error(t, err)
}

func TestAccessPolicyRepository_Update(t *testing.T) {
	t.Parallel()
	db := setupAccessPolicyTestDB(t)
	repo := repositories.NewAccessPolicyRepository(db)
	ctx := context.Background()

	policy := &model.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: model.PrincipalTypeUser,
		ResourceType:  model.PolicyResourceKeys,
		Operation:     model.OpCreate,
		Effect:        model.PolicyEffectAllow,
	}
	require.NoError(t, repo.Create(ctx, policy))

	policy.Effect = model.PolicyEffectDeny
	require.NoError(t, repo.Update(ctx, policy))

	updated, err := repo.GetByID(ctx, policy.ID)
	require.NoError(t, err)
	assert.Equal(t, model.PolicyEffectDeny, updated.Effect)
}
