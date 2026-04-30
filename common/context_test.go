package common

import (
	"context"
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
