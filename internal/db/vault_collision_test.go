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
	defer d.Close()
	_, err = d.Exec(`CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT, vault_id TEXT);
		INSERT INTO secrets VALUES ('11111111-1111-1111-1111-111111111111','dup','v1');
		INSERT INTO secrets VALUES ('22222222-2222-2222-2222-222222222222','dup','v1');
		INSERT INTO secrets VALUES ('33333333-3333-3333-3333-333333333333','unique','v1');`)
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
	defer d.Close()
	_, err = d.Exec(`CREATE TABLE keys (id TEXT PRIMARY KEY, name TEXT, vault_id TEXT);
		INSERT INTO keys VALUES ('a','k1','v1');
		INSERT INTO keys VALUES ('b','k2','v1');`)
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
	defer d.Close()
	_, err = d.Exec(`CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT, vault_id TEXT);
		INSERT INTO secrets VALUES ('a','same','vaultA');
		INSERT INTO secrets VALUES ('b','same','vaultB');`)
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
	defer d.Close()
	_, err = d.Exec(`CREATE TABLE secrets (id TEXT PRIMARY KEY, name TEXT, vault_id TEXT);
		INSERT INTO secrets VALUES ('deadbeef-1111-1111-1111-111111111111','dup','v1');
		INSERT INTO secrets VALUES ('deadbeef-2222-2222-2222-222222222222','dup','v1');
		INSERT INTO secrets VALUES ('deadbeef-3333-3333-3333-333333333333','dup','v1');`)
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
