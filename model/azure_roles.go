package model

import "sort"

// DataAction is an Azure Key Vault data-plane action string. It is the unit of
// authorization for every vault resource route: a route maps to exactly one
// action, and a role grants a fixed set of them. The strings match Azure's own
// data actions so Azure documentation and role scripts transfer unchanged.
type DataAction string

// Secret data actions.
const (
	// ActionSecretsReadMetadata permits listing secrets and reading their
	// metadata. It never exposes a secret value.
	ActionSecretsReadMetadata DataAction = "Microsoft.KeyVault/vaults/secrets/readMetadata/action"
	// ActionSecretsGet permits reading a secret value.
	ActionSecretsGet DataAction = "Microsoft.KeyVault/vaults/secrets/getSecret/action"
	// ActionSecretsSet permits creating a secret or writing a new value.
	ActionSecretsSet DataAction = "Microsoft.KeyVault/vaults/secrets/setSecret/action"
	// ActionSecretsDelete permits soft-deleting a secret.
	ActionSecretsDelete DataAction = "Microsoft.KeyVault/vaults/secrets/delete"
	// ActionSecretsBackup permits exporting a secret as a backup blob.
	ActionSecretsBackup DataAction = "Microsoft.KeyVault/vaults/secrets/backup/action"
	// ActionSecretsRestore permits importing a secret from a backup blob.
	ActionSecretsRestore DataAction = "Microsoft.KeyVault/vaults/secrets/restore/action"
	// ActionSecretsRecover permits undeleting a soft-deleted secret.
	ActionSecretsRecover DataAction = "Microsoft.KeyVault/vaults/secrets/recover/action"
	// ActionSecretsPurge permits permanently destroying a soft-deleted secret.
	ActionSecretsPurge DataAction = "Microsoft.KeyVault/vaults/secrets/purge"
)

// Key data actions.
const (
	// ActionKeysRead permits listing keys and reading key metadata and public
	// material. It never exposes private key material.
	ActionKeysRead DataAction = "Microsoft.KeyVault/vaults/keys/read"
	// ActionKeysCreate permits generating a new key.
	ActionKeysCreate DataAction = "Microsoft.KeyVault/vaults/keys/create"
	// ActionKeysUpdate permits changing key attributes and tags.
	ActionKeysUpdate DataAction = "Microsoft.KeyVault/vaults/keys/update"
	// ActionKeysDelete permits soft-deleting a key.
	ActionKeysDelete DataAction = "Microsoft.KeyVault/vaults/keys/delete"
	// ActionKeysBackup permits exporting a key as a backup blob.
	ActionKeysBackup DataAction = "Microsoft.KeyVault/vaults/keys/backup/action"
	// ActionKeysRestore permits importing a key from a backup blob.
	ActionKeysRestore DataAction = "Microsoft.KeyVault/vaults/keys/restore/action"
	// ActionKeysRecover permits undeleting a soft-deleted key.
	ActionKeysRecover DataAction = "Microsoft.KeyVault/vaults/keys/recover/action"
	// ActionKeysPurge permits permanently destroying a soft-deleted key.
	ActionKeysPurge DataAction = "Microsoft.KeyVault/vaults/keys/purge"
	// ActionKeysImport permits importing externally generated key material.
	// No HTTP route maps to it yet; it exists so the Crypto Officer and
	// Administrator bundles match Azure exactly.
	ActionKeysImport DataAction = "Microsoft.KeyVault/vaults/keys/import/action"
	// ActionKeysRotate permits rotating a key to a new version.
	ActionKeysRotate DataAction = "Microsoft.KeyVault/vaults/keys/rotate/action"
	// ActionKeysEncrypt permits encrypting with the key.
	ActionKeysEncrypt DataAction = "Microsoft.KeyVault/vaults/keys/encrypt/action"
	// ActionKeysDecrypt permits decrypting with the key.
	ActionKeysDecrypt DataAction = "Microsoft.KeyVault/vaults/keys/decrypt/action"
	// ActionKeysWrap permits wrapping another key with this key.
	ActionKeysWrap DataAction = "Microsoft.KeyVault/vaults/keys/wrap/action"
	// ActionKeysUnwrap permits unwrapping a key wrapped with this key.
	ActionKeysUnwrap DataAction = "Microsoft.KeyVault/vaults/keys/unwrap/action"
	// ActionKeysSign permits signing with the key.
	ActionKeysSign DataAction = "Microsoft.KeyVault/vaults/keys/sign/action"
	// ActionKeysVerify permits verifying a signature with the key.
	ActionKeysVerify DataAction = "Microsoft.KeyVault/vaults/keys/verify/action"
)

// Certificate data actions.
const (
	// ActionCertificatesRead permits listing certificates and reading a
	// certificate and its policy.
	ActionCertificatesRead DataAction = "Microsoft.KeyVault/vaults/certificates/read"
	// ActionCertificatesCreate permits issuing a new certificate.
	ActionCertificatesCreate DataAction = "Microsoft.KeyVault/vaults/certificates/create"
	// ActionCertificatesUpdate permits changing a certificate's attributes,
	// tags, or policy.
	ActionCertificatesUpdate DataAction = "Microsoft.KeyVault/vaults/certificates/update"
	// ActionCertificatesDelete permits soft-deleting a certificate.
	ActionCertificatesDelete DataAction = "Microsoft.KeyVault/vaults/certificates/delete"
	// ActionCertificatesBackup permits exporting a certificate as a backup blob.
	ActionCertificatesBackup DataAction = "Microsoft.KeyVault/vaults/certificates/backup/action"
	// ActionCertificatesRestore permits importing a certificate from a backup blob.
	ActionCertificatesRestore DataAction = "Microsoft.KeyVault/vaults/certificates/restore/action"
	// ActionCertificatesRecover permits undeleting a soft-deleted certificate.
	ActionCertificatesRecover DataAction = "Microsoft.KeyVault/vaults/certificates/recover/action"
	// ActionCertificatesPurge permits permanently destroying a soft-deleted
	// certificate.
	ActionCertificatesPurge DataAction = "Microsoft.KeyVault/vaults/certificates/purge"
)

// Vault-management and role-assignment data actions.
const (
	// ActionVaultPurge permits permanently purging a soft-deleted vault.
	// Unlike the per-object purge actions above, this applies to the vault
	// resource itself, not an object inside it.
	ActionVaultPurge DataAction = "Microsoft.KeyVault/vaults/purge/action"
	// ActionRoleAssignmentsWrite permits granting a role assignment in a vault.
	ActionRoleAssignmentsWrite DataAction = "Microsoft.Authorization/roleAssignments/write"
	// ActionRoleAssignmentsDelete permits revoking a role assignment in a vault.
	ActionRoleAssignmentsDelete DataAction = "Microsoft.Authorization/roleAssignments/delete"
)

// Azure built-in data-plane role names. A role is granted to a principal within
// a single vault via the role_assignments table; there is no tenant-wide grant.
const (
	// RoleKeyVaultAdministrator grants every data-plane action on every object type.
	RoleKeyVaultAdministrator = "Key Vault Administrator"
	// RoleKeyVaultReader grants metadata reads only: no secret values, no key material.
	RoleKeyVaultReader = "Key Vault Reader"
	// RoleKeyVaultSecretsUser grants get and list on secrets, including values.
	RoleKeyVaultSecretsUser = "Key Vault Secrets User"
	// RoleKeyVaultSecretsOfficer grants full control of secrets.
	RoleKeyVaultSecretsOfficer = "Key Vault Secrets Officer"
	// RoleKeyVaultCryptoUser grants use of key material: encrypt, decrypt, sign,
	// verify, wrap, unwrap.
	RoleKeyVaultCryptoUser = "Key Vault Crypto User"
	// RoleKeyVaultCryptoOfficer grants full control of keys, including create,
	// import, delete, and rotation.
	RoleKeyVaultCryptoOfficer = "Key Vault Crypto Officer"
	// RoleKeyVaultCertificatesOfficer grants full control of certificates.
	// RocketVault does not yet model a certificate as a linked key plus secret,
	// so this role grants no key or secret actions. That linkage is deferred to P5.
	RoleKeyVaultCertificatesOfficer = "Key Vault Certificates Officer"
)

// azureRoleDataActions is the single source of truth for what each role grants.
// Every bundle is written out in full: no bundle is derived from another, so a
// reader can see a role's exact authority without following a union.
var azureRoleDataActions = map[string][]DataAction{
	RoleKeyVaultAdministrator: {
		ActionSecretsReadMetadata, ActionSecretsGet, ActionSecretsSet,
		ActionSecretsDelete, ActionSecretsBackup, ActionSecretsRestore,
		ActionSecretsRecover, ActionSecretsPurge,
		ActionKeysRead, ActionKeysCreate, ActionKeysUpdate, ActionKeysDelete,
		ActionKeysBackup, ActionKeysRestore, ActionKeysRecover, ActionKeysPurge,
		ActionKeysImport, ActionKeysRotate, ActionKeysEncrypt, ActionKeysDecrypt,
		ActionKeysWrap, ActionKeysUnwrap, ActionKeysSign, ActionKeysVerify,
		ActionCertificatesRead, ActionCertificatesCreate, ActionCertificatesUpdate,
		ActionCertificatesDelete, ActionCertificatesBackup, ActionCertificatesRestore,
		ActionCertificatesRecover, ActionCertificatesPurge,
	},
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
		ActionKeysRead,
		ActionKeysEncrypt, ActionKeysDecrypt,
		ActionKeysWrap, ActionKeysUnwrap,
		ActionKeysSign, ActionKeysVerify,
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

// AzureRoleNames returns the seven built-in role names in sorted order.
func AzureRoleNames() []string {
	names := make([]string, 0, len(azureRoleDataActions))
	for name := range azureRoleDataActions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// IsAzureRole reports whether name is one of the seven built-in roles. The
// comparison is exact: role names are stored verbatim in role_assignments.role.
func IsAzureRole(name string) bool {
	_, ok := azureRoleDataActions[name]
	return ok
}

// AzureRoleDataActions returns a copy of the data actions role grants. An
// unknown role yields an empty slice, so an unrecognised assignment grants
// nothing rather than defaulting open.
func AzureRoleDataActions(role string) []DataAction {
	actions, ok := azureRoleDataActions[role]
	if !ok {
		return []DataAction{}
	}
	out := make([]DataAction, len(actions))
	copy(out, actions)
	return out
}

// RoleGrantsDataAction reports whether role grants action. An empty role, an
// unknown role, or an empty action always yields false.
func RoleGrantsDataAction(role string, action DataAction) bool {
	if role == "" || action == "" {
		return false
	}
	for _, a := range azureRoleDataActions[role] {
		if a == action {
			return true
		}
	}
	return false
}
