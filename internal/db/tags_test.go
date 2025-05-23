// Project: tags
package db

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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
		sqlDB.Close()
		DB = nil
	}
}

func TestTagRepository_AddTagsAndGetTags(t *testing.T) {
	db, cleanup := setupTagTestDB(t)
	defer cleanup()

	repo := NewTagRepository[struct{}](db, "secret_tags", "secret_id")
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

	repo := NewTagRepository[struct{}](db, "secret_tags", "secret_id")
	ctx := context.Background()
	id := uuid.New()

	got, err := repo.GetTags(ctx, id)
	assert.NoError(t, err)
	assert.Empty(t, got)
}

func TestTagRepository_AddTags_DBError(t *testing.T) {
	db, cleanup := setupTagTestDB(t)
	defer cleanup()
	repo := NewTagRepository[struct{}](db, "secret_tags", "secret_id")
	ctx := context.Background()
	id := uuid.New()
	_ = db.Close() // force DB error

	err := repo.AddTags(ctx, id, []string{"fail"})
	assert.Error(t, err)
}

func TestTagRepository_GetTags_DBError(t *testing.T) {
	db, cleanup := setupTagTestDB(t)
	defer cleanup()
	repo := NewTagRepository[struct{}](db, "secret_tags", "secret_id")
	ctx := context.Background()
	id := uuid.New()
	_ = db.Close() // force DB error

	_, err := repo.GetTags(ctx, id)
	assert.Error(t, err)
}
