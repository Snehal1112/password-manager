package repositories_test

import (
"context"
"database/sql"
"testing"

"github.com/google/uuid"
_ "github.com/mattn/go-sqlite3"
"github.com/stretchr/testify/assert"
"github.com/stretchr/testify/require"

"rocketvault/internal/domain"
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
	policy := &domain.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   principalID,
		PrincipalType: domain.PrincipalTypeUser,
		ResourceType:  domain.PolicyResourceSecrets,
		Operation:     domain.OpGet,
		Effect:        domain.PolicyEffectAllow,
	}

	require.NoError(t, repo.Create(ctx, policy))

	got, err := repo.GetByID(ctx, policy.ID)
	require.NoError(t, err)
	assert.Equal(t, policy.ID, got.ID)
	assert.Equal(t, domain.PolicyEffectAllow, got.Effect)
	assert.Equal(t, domain.PolicyResourceSecrets, got.ResourceType)
}

func TestAccessPolicyRepository_ListByPrincipal(t *testing.T) {
	t.Parallel()
	db := setupAccessPolicyTestDB(t)
	repo := repositories.NewAccessPolicyRepository(db)
	ctx := context.Background()

	principalID := uuid.New()
	otherID := uuid.New()

	p1 := &domain.AccessPolicy{
		ID: uuid.New(), PrincipalID: principalID, PrincipalType: domain.PrincipalTypeUser,
		ResourceType: domain.PolicyResourceSecrets, Operation: domain.OpGet, Effect: domain.PolicyEffectAllow,
	}
	p2 := &domain.AccessPolicy{
		ID: uuid.New(), PrincipalID: principalID, PrincipalType: domain.PrincipalTypeUser,
		ResourceType: domain.PolicyResourceKeys, Operation: domain.OpList, Effect: domain.PolicyEffectDeny,
	}
	p3 := &domain.AccessPolicy{
		ID: uuid.New(), PrincipalID: otherID, PrincipalType: domain.PrincipalTypeUser,
		ResourceType: domain.PolicyResourceSecrets, Operation: domain.OpList, Effect: domain.PolicyEffectAllow,
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
	p1 := &domain.AccessPolicy{
		ID: uuid.New(), PrincipalID: principalID, PrincipalType: domain.PrincipalTypeUser,
		ResourceType: domain.PolicyResourceSecrets, Operation: domain.OpDelete, Effect: domain.PolicyEffectAllow,
	}
	p2 := &domain.AccessPolicy{
		ID: uuid.New(), PrincipalID: principalID, PrincipalType: domain.PrincipalTypeUser,
		ResourceType: domain.PolicyResourceSecrets, Operation: domain.OpDelete, Effect: domain.PolicyEffectDeny,
	}
	require.NoError(t, repo.Create(ctx, p1))
	require.NoError(t, repo.Create(ctx, p2))

	effects, err := repo.FindEffects(ctx, principalID, domain.PolicyResourceSecrets, domain.OpDelete)
	require.NoError(t, err)
	assert.Len(t, effects, 2)

	hasDeny := false
	for _, e := range effects {
		if e.Effect == domain.PolicyEffectDeny {
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

	policy := &domain.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: domain.PrincipalTypeUser,
		ResourceType:  domain.PolicyResourceCertificates,
		Operation:     domain.OpGet,
		Effect:        domain.PolicyEffectAllow,
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

	policy := &domain.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   uuid.New(),
		PrincipalType: domain.PrincipalTypeUser,
		ResourceType:  domain.PolicyResourceKeys,
		Operation:     domain.OpCreate,
		Effect:        domain.PolicyEffectAllow,
	}
	require.NoError(t, repo.Create(ctx, policy))

	policy.Effect = domain.PolicyEffectDeny
	require.NoError(t, repo.Update(ctx, policy))

	updated, err := repo.GetByID(ctx, policy.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.PolicyEffectDeny, updated.Effect)
}
