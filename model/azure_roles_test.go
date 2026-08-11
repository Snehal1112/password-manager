package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAzureRoleNames asserts the exact seven built-in data-plane roles, sorted.
func TestAzureRoleNames(t *testing.T) {
	assert.Equal(t, []string{
		"Key Vault Administrator",
		"Key Vault Certificates Officer",
		"Key Vault Crypto Officer",
		"Key Vault Crypto User",
		"Key Vault Reader",
		"Key Vault Secrets Officer",
		"Key Vault Secrets User",
	}, AzureRoleNames())
}

// TestIsAzureRole accepts the seven names and rejects everything else,
// including the legacy vault role vocabulary and case variations.
func TestIsAzureRole(t *testing.T) {
	for _, name := range AzureRoleNames() {
		assert.True(t, IsAzureRole(name), "expected %q to be an Azure role", name)
	}
	for _, name := range []string{"", "vault-admin", "secrets-officer", "admin",
		"key vault administrator", "Key Vault Owner"} {
		assert.False(t, IsAzureRole(name), "expected %q not to be an Azure role", name)
	}
}

// TestAzureRoleDataActions pins the exact grant of every role. Any change to a
// role's bundle must change this table too.
func TestAzureRoleDataActions(t *testing.T) {
	cases := map[string][]DataAction{
		RoleKeyVaultReader: {
			ActionSecretsReadMetadata,
			ActionKeysRead,
			ActionCertificatesRead,
		},
		RoleKeyVaultSecretsUser: {
			ActionSecretsReadMetadata,
			ActionSecretsGet,
		},
		RoleKeyVaultSecretsOfficer: {
			ActionSecretsReadMetadata, ActionSecretsGet, ActionSecretsSet,
			ActionSecretsDelete, ActionSecretsBackup, ActionSecretsRestore,
			ActionSecretsRecover, ActionSecretsPurge,
		},
		RoleKeyVaultCryptoUser: {
			ActionKeysRead, ActionKeysEncrypt, ActionKeysDecrypt,
			ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify,
		},
		RoleKeyVaultCryptoOfficer: {
			ActionKeysRead, ActionKeysCreate, ActionKeysUpdate, ActionKeysDelete,
			ActionKeysBackup, ActionKeysRestore, ActionKeysRecover, ActionKeysPurge,
			ActionKeysImport, ActionKeysRotate, ActionKeysEncrypt, ActionKeysDecrypt,
			ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify,
		},
		RoleKeyVaultCertificatesOfficer: {
			ActionCertificatesRead, ActionCertificatesCreate, ActionCertificatesUpdate,
			ActionCertificatesDelete, ActionCertificatesBackup, ActionCertificatesRestore,
			ActionCertificatesRecover, ActionCertificatesPurge,
		},
	}
	for role, want := range cases {
		assert.ElementsMatch(t, want, AzureRoleDataActions(role), "role %q", role)
	}

	// Administrator holds every action any other role holds, and nothing else.
	var union []DataAction
	seen := map[DataAction]bool{}
	for _, role := range AzureRoleNames() {
		if role == RoleKeyVaultAdministrator {
			continue
		}
		for _, a := range AzureRoleDataActions(role) {
			if !seen[a] {
				seen[a] = true
				union = append(union, a)
			}
		}
	}
	admin := AzureRoleDataActions(RoleKeyVaultAdministrator)
	assert.Len(t, admin, 32, "administrator must grant all 32 data actions")
	for _, a := range union {
		assert.Contains(t, admin, a)
	}
}

// TestAzureRoleDataActionsUnknownRole returns an empty slice, never nil-panics.
func TestAzureRoleDataActionsUnknownRole(t *testing.T) {
	assert.Empty(t, AzureRoleDataActions("vault-admin"))
	assert.Empty(t, AzureRoleDataActions(""))
}

// TestAzureRoleDataActionsIsACopy proves the caller cannot mutate the table.
func TestAzureRoleDataActionsIsACopy(t *testing.T) {
	got := AzureRoleDataActions(RoleKeyVaultSecretsUser)
	require.Len(t, got, 2)
	got[0] = "tampered"
	assert.Equal(t, ActionSecretsReadMetadata, AzureRoleDataActions(RoleKeyVaultSecretsUser)[0])
}

// TestRoleGrantsDataAction covers the allow and deny directions and the
// fail-closed cases: unknown role, empty role, empty action.
func TestRoleGrantsDataAction(t *testing.T) {
	assert.True(t, RoleGrantsDataAction(RoleKeyVaultSecretsUser, ActionSecretsGet))
	assert.False(t, RoleGrantsDataAction(RoleKeyVaultSecretsUser, ActionSecretsSet))
	assert.True(t, RoleGrantsDataAction(RoleKeyVaultCryptoUser, ActionKeysSign))
	assert.False(t, RoleGrantsDataAction(RoleKeyVaultCryptoUser, ActionKeysCreate))
	assert.True(t, RoleGrantsDataAction(RoleKeyVaultAdministrator, ActionCertificatesPurge))
	assert.False(t, RoleGrantsDataAction("vault-admin", ActionSecretsGet))
	assert.False(t, RoleGrantsDataAction("", ActionSecretsGet))
	assert.False(t, RoleGrantsDataAction(RoleKeyVaultAdministrator, ""))
}

func TestNewDataActionConstants_MatchAzureStrings(t *testing.T) {
	cases := []struct {
		name string
		got  DataAction
		want DataAction
	}{
		{"vault purge", ActionVaultPurge, "Microsoft.KeyVault/vaults/purge/action"},
		{"role assignments write", ActionRoleAssignmentsWrite, "Microsoft.Authorization/roleAssignments/write"},
		{"role assignments delete", ActionRoleAssignmentsDelete, "Microsoft.Authorization/roleAssignments/delete"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Fatalf("got %q, want %q", c.got, c.want)
			}
		})
	}
}
