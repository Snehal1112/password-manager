package common

import (
	"context"
	"path/filepath"
	"testing"
)

func TestContextKey_String(t *testing.T) {
	// Each key must return a human-readable string for debugging.
	want := "rocketvault/user_id"
	if got := UserIDKey.String(); got != want {
		t.Errorf("UserIDKey.String() = %q, want %q", got, want)
	}
}

func TestContextKeyUsageInContext(t *testing.T) {
	ctx := context.Background()
	ctx = context.WithValue(ctx, UserIDKey, "test-user")
	val := ctx.Value(UserIDKey)
	if val != "test-user" {
		t.Errorf("expected value 'test-user', got %v", val)
	}
}

func withTempContextsDir(t *testing.T) {
	t.Helper()
	SessionBaseDir = filepath.Join(t.TempDir(), "sessions")
}

func TestAddAndListContexts(t *testing.T) {
	withTempContextsDir(t)

	if err := AddContext("prod", Context{Server: "https://vault.prod.example.com", Username: "admin"}); err != nil {
		t.Fatalf("AddContext: %v", err)
	}

	contexts, current, err := ListContexts()
	if err != nil {
		t.Fatalf("ListContexts: %v", err)
	}
	if current != "" {
		t.Errorf("current = %q, want empty (nothing set as current yet)", current)
	}
	got, ok := contexts["prod"]
	if !ok || got.Server != "https://vault.prod.example.com" || got.Username != "admin" {
		t.Errorf("contexts[prod] = %+v, ok=%v; want server/username set", got, ok)
	}
}

func TestUseAndCurrentContext(t *testing.T) {
	withTempContextsDir(t)
	AddContext("staging", Context{Server: "https://vault.staging.example.com"})

	if err := UseContext("staging"); err != nil {
		t.Fatalf("UseContext: %v", err)
	}

	ctx, name, err := CurrentContext()
	if err != nil || ctx == nil || name != "staging" {
		t.Fatalf("CurrentContext() = %+v, %q, %v; want staging", ctx, name, err)
	}
}

func TestUseContext_UnknownName_Errors(t *testing.T) {
	withTempContextsDir(t)
	if err := UseContext("does-not-exist"); err == nil {
		t.Fatal("UseContext(unknown) = nil error, want an error")
	}
}

func TestRemoveContext_ClearsCurrentIfActive(t *testing.T) {
	withTempContextsDir(t)
	AddContext("prod", Context{Server: "https://vault.prod.example.com"})
	UseContext("prod")

	if err := RemoveContext("prod"); err != nil {
		t.Fatalf("RemoveContext: %v", err)
	}

	ctx, name, err := CurrentContext()
	if err != nil || ctx != nil || name != "" {
		t.Fatalf("CurrentContext() after remove = %+v, %q, %v; want nil, \"\", nil", ctx, name, err)
	}
}

func TestUnsetCurrentContext_ClearsCurrentButKeepsContext(t *testing.T) {
	withTempContextsDir(t)
	AddContext("prod", Context{Server: "https://vault.prod.example.com"})
	UseContext("prod")

	if err := UnsetCurrentContext(); err != nil {
		t.Fatalf("UnsetCurrentContext: %v", err)
	}

	ctx, name, err := CurrentContext()
	if err != nil || ctx != nil || name != "" {
		t.Fatalf("CurrentContext() after unset = %+v, %q, %v; want nil, \"\", nil", ctx, name, err)
	}

	contexts, _, err := ListContexts()
	if err != nil {
		t.Fatalf("ListContexts: %v", err)
	}
	if _, ok := contexts["prod"]; !ok {
		t.Fatal("UnsetCurrentContext must not delete the saved context, only clear the current pointer")
	}
}

func TestUnsetCurrentContext_NoneSet_NoError(t *testing.T) {
	withTempContextsDir(t)
	if err := UnsetCurrentContext(); err != nil {
		t.Fatalf("UnsetCurrentContext() with nothing set = %v, want nil (no-op)", err)
	}
}

func TestCurrentContext_NoneSet_ReturnsNil(t *testing.T) {
	withTempContextsDir(t)
	ctx, name, err := CurrentContext()
	if err != nil || ctx != nil || name != "" {
		t.Fatalf("CurrentContext() = %+v, %q, %v; want nil, \"\", nil", ctx, name, err)
	}
}
