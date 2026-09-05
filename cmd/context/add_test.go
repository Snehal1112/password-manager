package contextcli

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

// newAddCmdForTest builds a `context add` command with its own contexts.json,
// matching how the tests above isolate state: contextsFilePath() is derived
// from SessionBaseDir, so pointing that at a temp dir is enough.
func newAddCmdForTest(t *testing.T) *cobra.Command {
	t.Helper()
	common.SessionBaseDir = filepath.Join(t.TempDir(), "sessions")

	parent := &cobra.Command{Use: "context"}
	parent.PersistentFlags().String("server", "", "")
	InitContextAdd(parent)
	return parent
}

func TestContextAdd_RejectsServerWithoutScheme(t *testing.T) {
	cmd := newAddCmdForTest(t)
	cmd.SetArgs([]string{"add", "prod", "--server", "vault.example.com"})
	err := cmd.Execute()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "scheme")
}

func TestContextAdd_RejectsServerWithNoHost(t *testing.T) {
	cmd := newAddCmdForTest(t)
	cmd.SetArgs([]string{"add", "prod", "--server", "https://"})
	err := cmd.Execute()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "host")
}

func TestContextAdd_AcceptsHTTPS(t *testing.T) {
	cmd := newAddCmdForTest(t)
	cmd.SetArgs([]string{"add", "prod", "--server", "https://vault.example.com"})
	require.NoError(t, cmd.Execute())
}

func TestContextAdd_AcceptsHTTP(t *testing.T) {
	cmd := newAddCmdForTest(t)
	cmd.SetArgs([]string{"add", "dev", "--server", "http://localhost:8774"})
	require.NoError(t, cmd.Execute())
}
