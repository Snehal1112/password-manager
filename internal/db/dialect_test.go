package db

import (
	"errors"
	"testing"

	"github.com/lib/pq"
	"github.com/mattn/go-sqlite3"
)

func TestDialectFromDriver(t *testing.T) {
	cases := map[string]Dialect{
		"postgres": Postgres,
		"sqlite3":  SQLite,
		"":         SQLite,
		"unknown":  SQLite,
	}
	for driver, want := range cases {
		if got := DialectFromDriver(driver); got != want {
			t.Errorf("DialectFromDriver(%q) = %v, want %v", driver, got, want)
		}
	}
}

func TestDialectRebind(t *testing.T) {
	const q = "SELECT * FROM t WHERE a = ? AND b = ?"

	if got := SQLite.Rebind(q); got != q {
		t.Errorf("SQLite.Rebind should be a no-op, got %q", got)
	}

	want := "SELECT * FROM t WHERE a = $1 AND b = $2"
	if got := Postgres.Rebind(q); got != want {
		t.Errorf("Postgres.Rebind = %q, want %q", got, want)
	}
}

func TestDialectUpsertIgnore(t *testing.T) {
	sqliteSQL := SQLite.UpsertIgnore("key_tags", "key_id, tag", "?, ?", "key_id, tag")
	if sqliteSQL != "INSERT OR IGNORE INTO key_tags (key_id, tag) VALUES (?, ?)" {
		t.Errorf("unexpected SQLite upsert: %q", sqliteSQL)
	}

	pgSQL := Postgres.UpsertIgnore("key_tags", "key_id, tag", "?, ?", "key_id, tag")
	want := "INSERT INTO key_tags (key_id, tag) VALUES (?, ?) ON CONFLICT (key_id, tag) DO NOTHING"
	if pgSQL != want {
		t.Errorf("unexpected Postgres upsert: %q", pgSQL)
	}
}

func TestDialectIsConstraintErr(t *testing.T) {
	if SQLite.IsConstraintErr(nil) {
		t.Error("nil error should not be a constraint error")
	}

	sqliteErr := sqlite3.Error{Code: sqlite3.ErrConstraint}
	if !SQLite.IsConstraintErr(sqliteErr) {
		t.Error("sqlite3.ErrConstraint should be a constraint error")
	}

	pgErr := &pq.Error{Code: "23505"}
	if !Postgres.IsConstraintErr(pgErr) {
		t.Error("pq 23505 should be a constraint error")
	}

	if SQLite.IsConstraintErr(errors.New("some other error")) {
		t.Error("generic error should not be a constraint error")
	}
}

func TestDialectIsDuplicateColumnErr(t *testing.T) {
	if SQLite.IsDuplicateColumnErr(errors.New("duplicate column name: foo")) == false {
		t.Error("sqlite duplicate-column message should match")
	}

	pgErr := &pq.Error{Code: "42701"}
	if !Postgres.IsDuplicateColumnErr(pgErr) {
		t.Error("pq 42701 should be a duplicate-column error")
	}

	if SQLite.IsDuplicateColumnErr(errors.New("syntax error")) {
		t.Error("unrelated error should not match")
	}
}

func TestDialectTimestampType(t *testing.T) {
	if SQLite.TimestampType() != "TIMESTAMP" || Postgres.TimestampType() != "TIMESTAMP" {
		t.Error("TimestampType should be TIMESTAMP on both engines")
	}
}
