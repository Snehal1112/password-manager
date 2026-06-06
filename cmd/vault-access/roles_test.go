package vaultaccess

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRolesCommand_ListsBuiltInRoles(t *testing.T) {
	parent := &cobra.Command{Use: "vault-access"}
	InitVaultAccessRoles(parent)

	var buf bytes.Buffer
	parent.SetOut(&buf)
	parent.SetArgs([]string{"roles"})
	if err := parent.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"secrets-user", "crypto-user", "vault-admin"} {
		if !strings.Contains(out, want) {
			t.Fatalf("roles output missing %q: %s", want, out)
		}
	}
}
