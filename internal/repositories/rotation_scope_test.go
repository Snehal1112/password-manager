package repositories_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	"rocketvault/model"
)

func TestRotationRepository_RejectsUninitializedScope(t *testing.T) {
	db := setupRotationDB(t)
	repo := repositories.NewRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), logging.InitLogger())
	ctx := context.Background()

	_, err := repo.Read(ctx, uuid.New(), model.Scope{})
	require.ErrorIs(t, err, repositories.ErrInvalidScope)

	now := time.Now()
	policy := &model.RotationPolicy{ID: uuid.New(), UserID: uuid.New(), VaultID: uuid.New(), Name: "p", IntervalDays: 30, CreatedAt: now, UpdatedAt: now}
	require.ErrorIs(t, repo.Update(ctx, policy, model.Scope{}), repositories.ErrInvalidScope)
	require.ErrorIs(t, repo.Delete(ctx, uuid.New(), model.Scope{}), repositories.ErrInvalidScope)

	_, err = repo.List(ctx, model.Scope{})
	require.ErrorIs(t, err, repositories.ErrInvalidScope)
}

func TestKeyRotationPolicyRepository_RejectsUninitializedScope(t *testing.T) {
	db := setupKeyRotationPolicyTestDB(t)
	repo := repositories.NewKeyRotationPolicyRepository(rvdb.NewConn(db, rvdb.SQLite), newKeyRotationPolicyTestLogger(t))
	ctx := context.Background()

	_, err := repo.GetByKeyID(ctx, uuid.New(), model.Scope{})
	require.ErrorIs(t, err, repositories.ErrInvalidScope)
	require.ErrorIs(t, repo.DeleteByKeyID(ctx, uuid.New(), model.Scope{}), repositories.ErrInvalidScope)
}
