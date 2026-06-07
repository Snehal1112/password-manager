package db

import "testing"

func TestResolveDriver_Explicit(t *testing.T) {
	cases := map[string]string{
		"sqlite3":    "sqlite3",
		"sqlite":     "sqlite3", // alias
		"postgres":   "postgres",
		"postgresql": "postgres", // alias
	}
	for in, want := range cases {
		got, err := resolveDriver(in, "ignored")
		if err != nil {
			t.Errorf("resolveDriver(%q): unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("resolveDriver(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveDriver_Invalid(t *testing.T) {
	if _, err := resolveDriver("mysql", "ignored"); err == nil {
		t.Error("expected error for unsupported driver mysql")
	}
}

func TestResolveDriver_SniffsFromConnString(t *testing.T) {
	cases := map[string]string{
		"./dev.db":                                    "sqlite3",
		":memory:":                                    "sqlite3",
		"file:test?mode=memory":                       "sqlite3",
		"postgres://user:pass@localhost:5432/rv":      "postgres",
		"postgresql://user:pass@localhost:5432/rv":    "postgres",
		"host=localhost user=rv dbname=rv sslmode=on": "postgres",
	}
	for conn, want := range cases {
		got, err := resolveDriver("", conn)
		if err != nil {
			t.Errorf("resolveDriver(\"\", %q): unexpected error %v", conn, err)
			continue
		}
		if got != want {
			t.Errorf("resolveDriver(\"\", %q) = %q, want %q", conn, got, want)
		}
	}
}
