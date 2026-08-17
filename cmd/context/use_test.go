package contextcli

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"rocketvault/common"
)

func TestContextUse_SetsCurrent(t *testing.T) {
	common.SessionBaseDir = filepath.Join(t.TempDir(), "sessions")
	common.AddContext("staging", common.Context{Server: "https://vault.staging.example.com"})

	parent := &cobra.Command{Use: "context"}
	InitContextUse(parent)

	parent.SetArgs([]string{"use", "staging"})
	if err := parent.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	_, name, err := common.CurrentContext()
	if err != nil || name != "staging" {
		t.Fatalf("CurrentContext() name = %q, %v; want staging", name, err)
	}
}

func TestContextUse_UnknownName_Errors(t *testing.T) {
	common.SessionBaseDir = filepath.Join(t.TempDir(), "sessions")

	parent := &cobra.Command{Use: "context"}
	InitContextUse(parent)

	parent.SetArgs([]string{"use", "does-not-exist"})
	if err := parent.Execute(); err == nil {
		t.Fatal("expected an error using an unknown context name")
	}
}
