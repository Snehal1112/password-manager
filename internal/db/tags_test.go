// Project: tags
package db

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTagTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	assert.NoError(t, err)
	_, err = sqlDB.Exec(`
		CREATE TABLE secret_tags (
			secret_id TEXT NOT NULL,
			tag TEXT NOT NULL,
			PRIMARY KEY (secret_id, tag)
		)
	`)
	assert.NoError(t, err)
	return sqlDB, func() {
		sqlDB.Close() //nolint:errcheck,gosec
	}
}

func TestTagRepository_AddTagsAndGetTags(t *testing.T) {
	db, cleanup := setupTagTestDB(t)
	defer cleanup()

	repo := NewTagRepository[struct{}](NewConn(db, SQLite), "secret_tags", "secret_id")
	ctx := context.Background()
	id := uuid.New()
	tags := []string{"prod", "api", "dev"}

	// Add tags
	err := repo.AddTags(ctx, id, tags)
	assert.NoError(t, err)

	// Add duplicate tags (should not error)
	err = repo.AddTags(ctx, id, []string{"prod"})
	assert.NoError(t, err)

	// Get tags
	got, err := repo.GetTags(ctx, id)
	assert.NoError(t, err, "got error while getting tags")
	assert.Len(t, got, len(tags), "expected number of tags to match")
	assert.ElementsMatch(t, tags, got, "expected tags to match")
}

func TestTagRepository_GetTags_Empty(t *testing.T) {
	db, cleanup := setupTagTestDB(t)
	defer cleanup()

	repo := NewTagRepository[struct{}](NewConn(db, SQLite), "secret_tags", "secret_id")
	ctx := context.Background()
	id := uuid.New()

	got, err := repo.GetTags(ctx, id)
	assert.NoError(t, err)
	assert.Empty(t, got)
}

func TestTagRepository_AddTags_DBError(t *testing.T) {
	db, cleanup := setupTagTestDB(t)
	defer cleanup()
	repo := NewTagRepository[struct{}](NewConn(db, SQLite), "secret_tags", "secret_id")
	ctx := context.Background()
	id := uuid.New()
	_ = db.Close() // force DB error

	err := repo.AddTags(ctx, id, []string{"fail"})
	assert.Error(t, err)
}

func TestTagRepository_GetTags_DBError(t *testing.T) {
	db, cleanup := setupTagTestDB(t)
	defer cleanup()
	repo := NewTagRepository[struct{}](NewConn(db, SQLite), "secret_tags", "secret_id")
	ctx := context.Background()
	id := uuid.New()
	_ = db.Close() // force DB error

	_, err := repo.GetTags(ctx, id)
	assert.Error(t, err)
}

// TestTagRepository_GetTagsForMany_NoCrossContamination guards the batch
// tag-fetch used by KeyRepository.List/CertificateRepository.List to avoid
// one query per row: each of several IDs has a distinct, multi-tag set, and
// every ID's returned tags must match only its own set — a slice-aliasing
// or indexing bug in the aggregation would blend tags across IDs.
func TestTagRepository_GetTagsForMany_NoCrossContamination(t *testing.T) {
	db, cleanup := setupTagTestDB(t)
	defer cleanup()

	repo := NewTagRepository[struct{}](NewConn(db, SQLite), "secret_tags", "secret_id")
	ctx := context.Background()

	id1, id2, id3 := uuid.New(), uuid.New(), uuid.New()
	require.NoError(t, repo.AddTags(ctx, id1, []string{"prod", "api"}))
	require.NoError(t, repo.AddTags(ctx, id2, []string{"staging"}))
	// id3 deliberately has no tags at all.

	got, err := repo.GetTagsForMany(ctx, []uuid.UUID{id1, id2, id3})
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"prod", "api"}, got[id1])
	assert.ElementsMatch(t, []string{"staging"}, got[id2])
	_, hasID3 := got[id3]
	assert.False(t, hasID3, "an ID with no tags should have no map entry")
}

func TestTagRepository_GetTagsForMany_EmptyIDsReturnsEmptyMapWithoutQuerying(t *testing.T) {
	db, cleanup := setupTagTestDB(t)
	defer cleanup()

	repo := NewTagRepository[struct{}](NewConn(db, SQLite), "secret_tags", "secret_id")
	_ = db.Close() // force a DB error if the implementation queries anyway

	got, err := repo.GetTagsForMany(context.Background(), nil)
	assert.NoError(t, err)
	assert.Empty(t, got)
}
