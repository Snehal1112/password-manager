package db

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestResolveNameCollisions_RenamesDuplicates(t *testing.T) {
	d, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close() //nolint:errcheck
	_, err = d.Exec(`CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT, vault_id TEXT, deleted_at TIMESTAMP NULL);
		INSERT INTO secrets VALUES ('11111111-1111-1111-1111-111111111111','dup','v1',NULL);
		INSERT INTO secrets VALUES ('22222222-2222-2222-2222-222222222222','dup','v1',NULL);
		INSERT INTO secrets VALUES ('33333333-3333-3333-3333-333333333333','unique','v1',NULL);`)
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := ResolveNameCollisions(context.Background(), NewConn(d, SQLite), "secrets")
	if err != nil {
		t.Fatalf("ResolveNameCollisions: %v", err)
	}
	if renamed != 1 {
		t.Fatalf("expected 1 rename, got %d", renamed)
	}
	var n int
	if err := d.QueryRow("SELECT COUNT(DISTINCT name) FROM secrets WHERE vault_id = 'v1'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("expected 3 distinct names after resolution, got %d", n)
	}
}

func TestResolveNameCollisions_NoDuplicatesIsNoop(t *testing.T) {
	d, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close() //nolint:errcheck
	_, err = d.Exec(`CREATE TABLE keys (id TEXT PRIMARY KEY, name TEXT, vault_id TEXT, deleted_at TIMESTAMP NULL);
		INSERT INTO keys VALUES ('a','k1','v1',NULL);
		INSERT INTO keys VALUES ('b','k2','v1',NULL);`)
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := ResolveNameCollisions(context.Background(), NewConn(d, SQLite), "keys")
	if err != nil {
		t.Fatal(err)
	}
	if renamed != 0 {
		t.Fatalf("expected 0 renames, got %d", renamed)
	}
}

func TestResolveNameCollisions_DifferentVaultsNotRenamed(t *testing.T) {
	d, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close() //nolint:errcheck
	_, err = d.Exec(`CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT, vault_id TEXT, deleted_at TIMESTAMP NULL);
		INSERT INTO secrets VALUES ('a','same','vaultA',NULL);
		INSERT INTO secrets VALUES ('b','same','vaultB',NULL);`)
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := ResolveNameCollisions(context.Background(), NewConn(d, SQLite), "secrets")
	if err != nil {
		t.Fatal(err)
	}
	if renamed != 0 {
		t.Fatalf("same name in different vaults must NOT be renamed, got %d renames", renamed)
	}
}

func TestResolveNameCollisions_ShortIDCollisionStillUnique(t *testing.T) {
	d, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close() //nolint:errcheck
	_, err = d.Exec(`CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT, vault_id TEXT, deleted_at TIMESTAMP NULL);
		INSERT INTO secrets VALUES ('deadbeef-1111-1111-1111-111111111111','dup','v1',NULL);
		INSERT INTO secrets VALUES ('deadbeef-2222-2222-2222-222222222222','dup','v1',NULL);
		INSERT INTO secrets VALUES ('deadbeef-3333-3333-3333-333333333333','dup','v1',NULL);`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveNameCollisions(context.Background(), NewConn(d, SQLite), "secrets"); err != nil {
		t.Fatal(err)
	}
	var distinct int
	if err := d.QueryRow("SELECT COUNT(DISTINCT name) FROM secrets WHERE vault_id='v1'").Scan(&distinct); err != nil {
		t.Fatal(err)
	}
	if distinct != 3 {
		t.Fatalf("expected 3 distinct names after resolving short-id collisions, got %d", distinct)
	}
	// And the unique index must now build without error.
	if _, err := d.Exec("CREATE UNIQUE INDEX idx_test ON secrets(vault_id, name)"); err != nil {
		t.Fatalf("unique index should build after collision resolution: %v", err)
	}
}

// newCollisionTable creates the minimal (id, name, vault_id, deleted_at) shape
// ResolveNameCollisions scans, on an in-memory database.
func newCollisionTable(t *testing.T, table string) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if _, err := d.Exec("CREATE TABLE " + table +
		" (id TEXT PRIMARY KEY, name TEXT, vault_id TEXT, deleted_at TIMESTAMP NULL)"); err != nil {
		t.Fatal(err)
	}
	return d
}

// TestResolveNameCollisions_SoftDeletedRowIsNotACollision covers the B50
// semantics change: the unique index is partial, so a soft-deleted row sharing
// (vault_id, name) with an ACTIVE row can never violate it. Neither row may be
// renamed -- least of all the active one, which is the row users still see.
func TestResolveNameCollisions_SoftDeletedRowIsNotACollision(t *testing.T) {
	d := newCollisionTable(t, "certificates")
	if _, err := d.Exec(`
		INSERT INTO certificates VALUES ('11111111-1111-1111-1111-111111111111','web-ca','v1','2026-08-01 00:00:00');
		INSERT INTO certificates VALUES ('22222222-2222-2222-2222-222222222222','web-ca','v1',NULL);`); err != nil {
		t.Fatal(err)
	}

	renamed, err := ResolveNameCollisions(context.Background(), NewConn(d, SQLite), "certificates")
	if err != nil {
		t.Fatal(err)
	}
	if renamed != 0 {
		t.Fatalf("a soft-deleted row sharing a name with an active one is not a collision, got %d renames", renamed)
	}

	var deletedName, activeName string
	if err := d.QueryRow(
		"SELECT name FROM certificates WHERE id = '11111111-1111-1111-1111-111111111111'").Scan(&deletedName); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(
		"SELECT name FROM certificates WHERE id = '22222222-2222-2222-2222-222222222222'").Scan(&activeName); err != nil {
		t.Fatal(err)
	}
	if deletedName != "web-ca" {
		t.Fatalf("the soft-deleted row must keep its name, got %q", deletedName)
	}
	if activeName != "web-ca" {
		t.Fatalf("the ACTIVE row must never be renamed for a soft-deleted namesake, got %q", activeName)
	}

	// The partial index the caller creates next must build over this data.
	if _, err := d.Exec(
		"CREATE UNIQUE INDEX idx_test ON certificates(vault_id, name) WHERE deleted_at IS NULL"); err != nil {
		t.Fatalf("partial unique index should build without renaming anything: %v", err)
	}
}

// TestResolveNameCollisions_TwoSoftDeletedRowsAreNotACollision pins the other
// half: two soft-deleted rows are entirely outside what a partial index
// enforces, so they must be left alone as well.
func TestResolveNameCollisions_TwoSoftDeletedRowsAreNotACollision(t *testing.T) {
	d := newCollisionTable(t, "keys")
	if _, err := d.Exec(`
		INSERT INTO keys VALUES ('a','signing','v1','2026-08-01 00:00:00');
		INSERT INTO keys VALUES ('b','signing','v1','2026-08-02 00:00:00');`); err != nil {
		t.Fatal(err)
	}

	renamed, err := ResolveNameCollisions(context.Background(), NewConn(d, SQLite), "keys")
	if err != nil {
		t.Fatal(err)
	}
	if renamed != 0 {
		t.Fatalf("two soft-deleted rows are not a collision under a partial index, got %d renames", renamed)
	}

	var n int
	if err := d.QueryRow("SELECT COUNT(*) FROM keys WHERE name = 'signing'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("both soft-deleted rows must keep their name, got %d rows still named 'signing'", n)
	}
}

// TestResolveNameCollisions_ActiveDuplicatesStillRenamedAlongsideSoftDeleted
// keeps the function's real job intact: two ACTIVE rows sharing a name are still
// a genuine collision and must be resolved, even when a soft-deleted row is
// sitting on the same name and must itself be left untouched.
func TestResolveNameCollisions_ActiveDuplicatesStillRenamedAlongsideSoftDeleted(t *testing.T) {
	d := newCollisionTable(t, "secrets")
	if _, err := d.Exec(`
		INSERT INTO secrets VALUES ('11111111-1111-1111-1111-111111111111','dup','v1','2026-08-01 00:00:00');
		INSERT INTO secrets VALUES ('22222222-2222-2222-2222-222222222222','dup','v1',NULL);
		INSERT INTO secrets VALUES ('33333333-3333-3333-3333-333333333333','dup','v1',NULL);`); err != nil {
		t.Fatal(err)
	}

	renamed, err := ResolveNameCollisions(context.Background(), NewConn(d, SQLite), "secrets")
	if err != nil {
		t.Fatal(err)
	}
	if renamed != 1 {
		t.Fatalf("expected exactly the second ACTIVE row to be renamed, got %d renames", renamed)
	}

	var deletedName string
	if err := d.QueryRow(
		"SELECT name FROM secrets WHERE id = '11111111-1111-1111-1111-111111111111'").Scan(&deletedName); err != nil {
		t.Fatal(err)
	}
	if deletedName != "dup" {
		t.Fatalf("the soft-deleted row must not be renamed, got %q", deletedName)
	}

	// The partial index must now build.
	if _, err := d.Exec(
		"CREATE UNIQUE INDEX idx_test ON secrets(vault_id, name) WHERE deleted_at IS NULL"); err != nil {
		t.Fatalf("partial unique index should build after resolving the active duplicates: %v", err)
	}
}
