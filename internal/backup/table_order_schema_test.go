package backup

import (
	"database/sql"
	"sort"
	"testing"

	rvdb "rocketvault/internal/db"
	"rocketvault/internal/logging"
)

// TestTableDependencies_MatchesLiveSchema proves table_order.go's hardcoded
// tableDependencies map agrees with the real schema's FK constraints,
// queried live via SQLite's PRAGMA foreign_key_list. If a future migration
// adds a table or a foreign key without updating tableDependencies, this
// test fails -- instead of silently reintroducing the ordering bug this
// plan fixes (Critical Finding #9).
//
// It also proves every table the live schema creates has SOME entry in
// tableDependencies (even an empty one), so a brand-new table can't be
// silently treated as dependency-free by topologicalOrder's own defensive
// fallback without a human having actually looked at it.
func TestTableDependencies_MatchesLiveSchema(t *testing.T) {
	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()

	repo := rvdb.NewRepository(logging.InitLogger())
	if err := repo.SetupSchema(sqlDB, rvdb.SQLite); err != nil {
		t.Fatalf("setup schema: %v", err)
	}

	liveTables, err := queryLiveTableNames(sqlDB)
	if err != nil {
		t.Fatal(err)
	}

	for _, table := range liveTables {
		wantParents, known := tableDependencies[table]
		if !known {
			t.Errorf("table %q exists in the live schema but has no entry in tableDependencies -- add one (table_order.go)", table)
			continue
		}

		gotParents, err := queryLiveForeignKeyParents(sqlDB, table)
		if err != nil {
			t.Fatalf("query FK parents for %q: %v", table, err)
		}

		sort.Strings(wantParents)
		sort.Strings(gotParents)
		if !equalStringSlices(wantParents, gotParents) {
			t.Errorf("table %q: tableDependencies says parents=%v, live schema FK constraints say parents=%v -- update table_order.go", table, wantParents, gotParents)
		}
	}

	// Reverse direction: every table tableDependencies knows about should
	// still exist in the live schema (catches a removed/renamed table left
	// stale in the map).
	liveSet := make(map[string]bool, len(liveTables))
	for _, t := range liveTables {
		liveSet[t] = true
	}
	for table := range tableDependencies {
		if !liveSet[table] {
			t.Errorf("tableDependencies has an entry for %q, but no such table exists in the live schema -- remove it from table_order.go", table)
		}
	}
}

func queryLiveTableNames(sqlDB *sql.DB) ([]string, error) {
	rows, err := sqlDB.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tables = append(tables, name)
	}
	return tables, rows.Err()
}

func queryLiveForeignKeyParents(sqlDB *sql.DB, table string) ([]string, error) {
	// PRAGMA calls don't support parameter binding; table names here come
	// only from queryLiveTableNames's own sqlite_master read, never from
	// external input.
	rows, err := sqlDB.Query(`PRAGMA foreign_key_list(` + table + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	parentSet := make(map[string]bool)
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		for i, col := range cols {
			if col == "table" {
				if s, ok := vals[i].(string); ok {
					parentSet[s] = true
				}
			}
		}
	}

	parents := make([]string, 0, len(parentSet))
	for p := range parentSet {
		parents = append(parents, p)
	}
	return parents, rows.Err()
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
