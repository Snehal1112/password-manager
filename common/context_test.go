package common

import (
	"context"
	"testing"
)

func TestContextKey_String(t *testing.T) {
	key := UserIDKey
	want := "userID"
	if key.String() != want {
		t.Errorf("ContextKey.String() = %q, want %q", key.String(), want)
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
