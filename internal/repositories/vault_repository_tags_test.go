package repositories

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
	"rocketvault/model"
)

func newVaultTagsTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	_, err = db.Exec(`CREATE TABLE vaults (
		id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		purge_protection BOOLEAN NOT NULL DEFAULT FALSE,
		retention_days INTEGER NOT NULL DEFAULT 90,
		created_by TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP NULL, scheduled_purge_at TIMESTAMP NULL,
		tags TEXT NOT NULL DEFAULT '{}', updated_at TIMESTAMP NULL, updated_by TEXT NULL
	)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

func TestVaultRepository_EmptyTagsClears(t *testing.T) {
	db := newVaultTagsTestDB(t)
	defer db.Close() //nolint:errcheck
	repo := NewVaultRepository(rvdb.NewConn(db, rvdb.SQLite), &logging.Logger{})
	ctx := context.Background()

	v := &model.Vault{
		ID: uuid.New(), Name: "clearme", Enabled: true, RetentionDays: 90,
		CreatedBy: uuid.New(), Tags: map[string]string{"env": "prod"},
	}
	if err := repo.Create(ctx, v); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.ReadByName(ctx, "clearme")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got.Tags = map[string]string{}
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	after, err := repo.ReadByName(ctx, "clearme")
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if len(after.Tags) != 0 {
		t.Fatalf("expected tags cleared, got %v", after.Tags)
	}
}

func TestVaultRepository_TagsRoundTripAndUpdateStamps(t *testing.T) {
	db := newVaultTagsTestDB(t)
	defer db.Close() //nolint:errcheck
	repo := NewVaultRepository(rvdb.NewConn(db, rvdb.SQLite), &logging.Logger{})
	ctx := context.Background()

	creator := uuid.New()
	v := &model.Vault{
		ID: uuid.New(), Name: "tagged", Enabled: true, RetentionDays: 90,
		CreatedBy: creator, Tags: map[string]string{"env": "prod"},
	}
	if err := repo.Create(ctx, v); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := repo.ReadByName(ctx, "tagged")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Tags["env"] != "prod" {
		t.Fatalf("tags not round-tripped: %v", got.Tags)
	}

	updater := uuid.New()
	got.Tags = map[string]string{"team": "billing"}
	got.UpdatedBy = &updater
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}

	after, err := repo.ReadByName(ctx, "tagged")
	if err != nil {
		t.Fatalf("read after update: %v", err)
	}
	if after.Tags["team"] != "billing" || after.Tags["env"] != "" {
		t.Fatalf("update did not replace tags: %v", after.Tags)
	}
	if after.UpdatedAt == nil {
		t.Fatal("updated_at was not stamped")
	}
	if after.UpdatedBy == nil || *after.UpdatedBy != updater {
		t.Fatalf("updated_by not persisted: %v", after.UpdatedBy)
	}
}
