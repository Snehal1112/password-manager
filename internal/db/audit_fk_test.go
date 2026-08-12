// Regression test for the audit_logs.user_id foreign-key bug.
//
// audit_logs.user_id used to FK-reference users(id) ON DELETE SET NULL. Task 3
// (OAuth2 token-issuance auditing) writes the OAuth2 client's NAME into that
// column, which is never a users.id row. SQLite never enforced this FK
// (foreign_keys PRAGMA is off by default in this project), so the bug was
// invisible in dev/test, but PostgreSQL enforces it in production and the
// insert failed there, silently dropping OAuth2 audit events (AuditService
// swallows insert errors by design). The fix drops the FK from the fresh-
// install schema entirely and, on upgrade, drops it explicitly on Postgres
// via migrateSchema (SQLite has nothing to migrate since it never had an
// enforced constraint to begin with).
package db

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/require"

	"rocketvault/internal/logging"
)

// TestAuditLogs_UserIDHasNoForeignKey verifies that a freshly created
// audit_logs table (createOptimizedSchema, the fresh-install path) declares
// no foreign key on user_id at all, and that inserting an arbitrary
// non-users.id string into user_id succeeds — proving the FK is genuinely
// gone rather than merely unenforced.
func TestAuditLogs_UserIDHasNoForeignKey(t *testing.T) {
	conn, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	d := NewRepository(logging.InitLogger())
	require.NoError(t, d.createOptimizedSchema(conn), "createOptimizedSchema should succeed")
	require.NoError(t, d.migrateSchema(conn), "migrateSchema should succeed")

	// SQLite exposes declared foreign keys via PRAGMA regardless of whether
	// enforcement (the foreign_keys PRAGMA) is on. There must be none for
	// audit_logs — the CREATE TABLE literal no longer declares one.
	rows, err := conn.Query(`PRAGMA foreign_key_list(audit_logs)`)
	require.NoError(t, err)
	defer rows.Close() //nolint:errcheck
	require.False(t, rows.Next(), "audit_logs must declare no foreign keys")
	require.NoError(t, rows.Err())

	// An OAuth2 client NAME (never a users.id row) must insert cleanly, the
	// same shape of write Task 3's recordOAuth2TokenAudit performs.
	_, err = conn.Exec(
		`INSERT INTO audit_logs (id, user_id, action, resource_type, resource_id, outcome, source)
		 VALUES ('a1', 'my-oauth2-client-name', 'oauth2_token_issue', 'oauth2_client', 'my-oauth2-client-name', 'success', 'api')`,
	)
	require.NoError(t, err, "inserting a non-users.id string into user_id must succeed now that the FK is gone")
}
