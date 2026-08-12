package vaultaccess

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	authz "rocketvault/internal/services/authorization"
	"rocketvault/model"
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

// TestRolesCommand_EveryNameIsLegacyOrAzure locks in the invariant the roles
// command's RunE relies on: authz.BuiltInRoleNames() only ever yields names
// that are either legacy or an Azure built-in role. If this ever stops being
// true, RunE now returns an explicit internal error instead of silently
// dropping the unrecognized name from the output.
func TestRolesCommand_EveryNameIsLegacyOrAzure(t *testing.T) {
	for _, name := range authz.BuiltInRoleNames() {
		if !authz.IsLegacyRole(name) && !model.IsAzureRole(name) {
			t.Fatalf("BuiltInRoleNames() returned %q, which is neither legacy nor an Azure role", name)
		}
	}
}
