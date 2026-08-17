// internal/cliclient/localonly_test.go
package cliclient

import (
	"path/filepath"
	"strings"
	"testing"

	"rocketvault/common"
)

func TestRequireLocal_NoTarget_ReturnsNil(t *testing.T) {
	// Without this, a nil serverFlag/env falls through to
	// common.CurrentContext(), which reads the real
	// ~/.rocketvault/contexts.json -- flaky for any dev/CI runner that has
	// ever run `context use`. See I3, 2026-08-17 final review.
	common.SessionBaseDir = filepath.Join(t.TempDir(), "sessions")
	t.Setenv("ROCKETVAULT_ADDR", "")
	if err := RequireLocal("", "master-key rotate"); err != nil {
		t.Fatalf("RequireLocal() = %v, want nil (local mode)", err)
	}
}

func TestRequireLocal_ServerFlagSet_ReturnsError(t *testing.T) {
	err := RequireLocal("https://vault.prod.example.com", "master-key rotate")
	if err == nil {
		t.Fatal("RequireLocal() = nil, want an error when a remote target is resolved")
	}
	for _, want := range []string{"master-key rotate", "local-only", "--server"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message %q missing expected substring %q", err.Error(), want)
		}
	}
}

func TestRequireLocal_EnvSet_ReturnsError(t *testing.T) {
	t.Setenv("ROCKETVAULT_ADDR", "https://vault.prod.example.com")
	if err := RequireLocal("", "backup create"); err == nil {
		t.Fatal("RequireLocal() = nil, want an error when ROCKETVAULT_ADDR is set")
	}
}
