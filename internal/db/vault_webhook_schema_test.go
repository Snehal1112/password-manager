package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

// vaultWebhookMigratePrereqSQL creates the minimal old-shape tables migrateSchema's
// earlier statements (ALTER TABLE / FK-bearing CREATE TABLE) require in order to
// run cleanly end to end, matching the fixture TestMigrateSchema_AddsAssignmentIDIdempotent
// (migrate_assignment_test.go) already uses to exercise migrateSchema standalone
// against an in-memory database that was never touched by createOptimizedSchema.
const vaultWebhookMigratePrereqSQL = `
	CREATE TABLE users (
		id       TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		role     TEXT NOT NULL
	);
	CREATE TABLE secrets (
		id   TEXT PRIMARY KEY,
		name TEXT NOT NULL
	);
	CREATE TABLE keys (
		id   TEXT PRIMARY KEY,
		name TEXT NOT NULL
	);
	CREATE TABLE certificates (
		id   TEXT PRIMARY KEY,
		name TEXT NOT NULL
	);
	CREATE TABLE audit_logs (
		id TEXT PRIMARY KEY
	);
	CREATE TABLE access_policies (
		id             TEXT PRIMARY KEY,
		principal_id   TEXT NOT NULL,
		principal_type TEXT NOT NULL,
		resource_type  TEXT NOT NULL,
		operation      TEXT NOT NULL,
		effect         TEXT NOT NULL,
		created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
`

// TestVaultWebhookConfigsTable_CreatedByBothSchemaPaths proves the table is
// registered in createOptimizedSchema AND migrateSchema. Registering it in
// only one leaves either fresh installs or upgraded installs without it --
// the exact dual-registration requirement key_rotation_policies has.
//
// createOptimizedSchema and migrateSchema are methods on *DBRepository (not
// package-level functions taking *sql.DB, as an earlier draft of this test
// assumed) -- see internal/db/db.go's createOptimizedSchema/migrateSchema.
// A method value such as repo.createOptimizedSchema has type func(*sql.DB)
// error, so the table-driven run field below stays exactly that signature.
//
// migrateSchema cannot run against a truly empty database -- its earlier
// statements are ALTER TABLE ... against secrets/keys/certificates/etc.,
// which fail with "no such table" (not a swallowed duplicate-column error)
// if those tables don't already exist. So the migrateSchema subtest seeds
// the same old-shape prerequisite tables migrate_assignment_test.go uses for
// the same reason.
func TestVaultWebhookConfigsTable_CreatedByBothSchemaPaths(t *testing.T) {
	repo := NewRepository(logging.InitLogger())

	for _, tc := range []struct {
		name  string
		setup func(*sql.DB)
		run   func(*sql.DB) error
	}{
		{"createOptimizedSchema", func(*sql.DB) {}, repo.createOptimizedSchema},
		{"migrateSchema", func(db *sql.DB) {
			_, err := db.Exec(vaultWebhookMigratePrereqSQL)
			require.NoError(t, err)
		}, repo.migrateSchema},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database, err := sql.Open("sqlite3", ":memory:")
			require.NoError(t, err)
			defer database.Close() //nolint:errcheck

			tc.setup(database)
			require.NoError(t, tc.run(database))

			var name string
			err = database.QueryRow(
				"SELECT name FROM sqlite_master WHERE type='table' AND name='vault_webhook_configs'",
			).Scan(&name)
			require.NoError(t, err, "vault_webhook_configs missing from %s", tc.name)
			require.Equal(t, "vault_webhook_configs", name)
		})
	}
}

// TestVaultWebhookConfigsTable_VaultIDIsUnique proves the one-config-per-vault
// invariant is enforced by the schema, not just by convention in the service.
// The inserted vault_id has no matching row in vaults; that's fine because
// SQLite never enforces the FOREIGN KEY clause in this project (the
// foreign_keys PRAGMA is off, see internal/db/db.go), so this test can
// exercise the UNIQUE constraint in isolation without a real vaults row.
func TestVaultWebhookConfigsTable_VaultIDIsUnique(t *testing.T) {
	database, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer database.Close() //nolint:errcheck

	repo := NewRepository(logging.InitLogger())
	require.NoError(t, repo.createOptimizedSchema(database))

	insert := `INSERT INTO vault_webhook_configs
		(id, vault_id, url, signing_secret_encrypted, enabled)
		VALUES (?, ?, ?, ?, ?)`
	_, err = database.Exec(insert, "id-1", "vault-1", "https://a.example", "ct", true)
	require.NoError(t, err)

	_, err = database.Exec(insert, "id-2", "vault-1", "https://b.example", "ct", true)
	require.Error(t, err, "a second config for the same vault must violate UNIQUE(vault_id)")
}
