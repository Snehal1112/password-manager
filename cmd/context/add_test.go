package contextcli

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"rocketvault/common"
)

func TestContextAdd_RequiresServerFlag(t *testing.T) {
	common.SessionBaseDir = filepath.Join(t.TempDir(), "sessions")

	parent := &cobra.Command{Use: "context"}
	parent.PersistentFlags().String("server", "", "")
	InitContextAdd(parent)

	parent.SetArgs([]string{"add", "prod"})
	if err := parent.Execute(); err == nil {
		t.Fatal("expected an error when --server is not provided")
	}
}

func TestContextAdd_SavesContext(t *testing.T) {
	common.SessionBaseDir = filepath.Join(t.TempDir(), "sessions")

	parent := &cobra.Command{Use: "context"}
	parent.PersistentFlags().String("server", "", "")
	InitContextAdd(parent)

	parent.SetArgs([]string{"add", "prod", "--server", "https://vault.prod.example.com", "--default-username", "admin"})
	if err := parent.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	contexts, _, err := common.ListContexts()
	if err != nil {
		t.Fatalf("ListContexts: %v", err)
	}
	got, ok := contexts["prod"]
	if !ok || got.Server != "https://vault.prod.example.com" || got.Username != "admin" {
		t.Fatalf("contexts[prod] = %+v, ok=%v; want server/username set", got, ok)
	}
}
