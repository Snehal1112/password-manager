package contextcli

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"rocketvault/common"
)

func TestContextUnset_ClearsCurrentButKeepsContext(t *testing.T) {
	common.SessionBaseDir = filepath.Join(t.TempDir(), "sessions")
	common.AddContext("staging", common.Context{Server: "https://vault.staging.example.com"})
	common.UseContext("staging")

	parent := &cobra.Command{Use: "context"}
	InitContextUnset(parent)

	parent.SetArgs([]string{"unset"})
	if err := parent.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	_, name, err := common.CurrentContext()
	if err != nil || name != "" {
		t.Fatalf("CurrentContext() name = %q, %v; want empty (local mode)", name, err)
	}

	contexts, _, err := common.ListContexts()
	if err != nil {
		t.Fatalf("ListContexts: %v", err)
	}
	if _, ok := contexts["staging"]; !ok {
		t.Fatal("context unset must not delete the saved context")
	}
}

func TestContextUnset_NoneSet_NoError(t *testing.T) {
	common.SessionBaseDir = filepath.Join(t.TempDir(), "sessions")

	parent := &cobra.Command{Use: "context"}
	InitContextUnset(parent)

	parent.SetArgs([]string{"unset"})
	if err := parent.Execute(); err != nil {
		t.Fatalf("Execute() with no current context set = %v, want nil (no-op)", err)
	}
}
