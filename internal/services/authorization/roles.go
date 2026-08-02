package authorization

import (
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"rocketvault/model"
)

// permission is one (resource_type, operation) pair within a role bundle.
type permission struct {
	Resource  model.PolicyResourceType
	Operation model.PolicyOperation
}

// builtInRoles maps each built-in vault role to its permission bundle.
// Only operations defined in model/access_policy.go are used (no wrap/unwrap).
var builtInRoles = map[string][]permission{
	"vault-reader": {
		{model.PolicyResourceSecrets, model.OpGet}, {model.PolicyResourceSecrets, model.OpList},
		{model.PolicyResourceKeys, model.OpGet}, {model.PolicyResourceKeys, model.OpList},
		{model.PolicyResourceCertificates, model.OpGet}, {model.PolicyResourceCertificates, model.OpList},
	},
	"secrets-user": {
		{model.PolicyResourceSecrets, model.OpGet}, {model.PolicyResourceSecrets, model.OpList},
	},
	"secrets-officer": {
		{model.PolicyResourceSecrets, model.OpGet}, {model.PolicyResourceSecrets, model.OpList},
		{model.PolicyResourceSecrets, model.OpSet}, {model.PolicyResourceSecrets, model.OpDelete},
		{model.PolicyResourceSecrets, model.OpBackup}, {model.PolicyResourceSecrets, model.OpRestore},
		{model.PolicyResourceSecrets, model.OpRecover}, {model.PolicyResourceSecrets, model.OpPurge},
	},
	"crypto-user": {
		{model.PolicyResourceKeys, model.OpGet}, {model.PolicyResourceKeys, model.OpList},
		{model.PolicyResourceKeys, model.OpSign}, {model.PolicyResourceKeys, model.OpVerify},
		{model.PolicyResourceKeys, model.OpEncrypt}, {model.PolicyResourceKeys, model.OpDecrypt},
	},
	"crypto-officer": {
		{model.PolicyResourceKeys, model.OpGet}, {model.PolicyResourceKeys, model.OpList},
		{model.PolicyResourceKeys, model.OpCreate}, {model.PolicyResourceKeys, model.OpDelete},
		{model.PolicyResourceKeys, model.OpRotate}, {model.PolicyResourceKeys, model.OpBackup},
		{model.PolicyResourceKeys, model.OpRestore}, {model.PolicyResourceKeys, model.OpRecover},
		{model.PolicyResourceKeys, model.OpPurge}, {model.PolicyResourceKeys, model.OpImport},
	},
	"certificates-officer": {
		{model.PolicyResourceCertificates, model.OpGet}, {model.PolicyResourceCertificates, model.OpList},
		{model.PolicyResourceCertificates, model.OpCreate}, {model.PolicyResourceCertificates, model.OpDelete},
		{model.PolicyResourceCertificates, model.OpRenew}, {model.PolicyResourceCertificates, model.OpBackup},
		{model.PolicyResourceCertificates, model.OpRestore}, {model.PolicyResourceCertificates, model.OpRecover},
		{model.PolicyResourceCertificates, model.OpPurge},
	},
}

// vaultAdminExtra is the additional management permission for vault-admin.
var vaultAdminExtra = permission{model.PolicyResourceVaults, model.OpManage}

// BuiltInRoleNames returns the sorted list of grantable role names: the legacy
// vault roles plus the seven Azure built-in data-plane roles.
func BuiltInRoleNames() []string {
	names := make([]string, 0, len(builtInRoles)+1+len(model.AzureRoleNames()))
	for n := range builtInRoles {
		names = append(names, n)
	}
	names = append(names, "vault-admin")
	names = append(names, model.AzureRoleNames()...)
	sort.Strings(names)
	return names
}

// RolePermissions returns the (resource, operation) pairs for display. Azure
// built-in roles are not expressed in this legacy permission vocabulary; they
// grant data actions instead, so they report an empty set. Use
// model.AzureRoleDataActions for those.
func RolePermissions(role string) ([][2]string, error) {
	if model.IsAzureRole(role) {
		return [][2]string{}, nil
	}
	perms, err := bundle(role)
	if err != nil {
		return nil, err
	}
	out := make([][2]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, [2]string{string(p.Resource), string(p.Operation)})
	}
	return out, nil
}

// IsValidRole reports whether name is a grantable role: a legacy vault role or
// one of the seven Azure built-in data-plane roles.
func IsValidRole(name string) bool {
	if name == "vault-admin" || model.IsAzureRole(name) {
		return true
	}
	_, ok := builtInRoles[name]
	return ok
}

// bundle returns the full permission set for a role, including vault-admin's union.
func bundle(role string) ([]permission, error) {
	if role == "vault-admin" {
		seen := map[permission]bool{}
		var all []permission
		for _, perms := range builtInRoles {
			for _, p := range perms {
				if !seen[p] {
					seen[p] = true
					all = append(all, p)
				}
			}
		}
		all = append(all, vaultAdminExtra)
		return all, nil
	}
	perms, ok := builtInRoles[role]
	if !ok {
		return nil, fmt.Errorf("unknown role %q", role)
	}
	return perms, nil
}

// ExpandRole turns a role grant into the access_policies rows it implies.
//
// Azure built-in roles expand to nothing: they are evaluated directly from the
// role_assignments row by MapRouteToDataAction plus model.RoleGrantsDataAction.
// Materialising a second, derived copy of the same grant in access_policies
// would create two sources of truth that can drift, and access_policies is
// retained only as an explicit-deny override.
func ExpandRole(role string, principalID uuid.UUID, principalType model.PrincipalType, vaultID, assignmentID uuid.UUID) ([]*model.AccessPolicy, error) {
	if model.IsAzureRole(role) {
		return nil, nil
	}
	perms, err := bundle(role)
	if err != nil {
		return nil, err
	}
	v := vaultID
	a := assignmentID
	now := time.Now().UTC()
	policies := make([]*model.AccessPolicy, 0, len(perms))
	for _, p := range perms {
		policies = append(policies, &model.AccessPolicy{
			ID:            uuid.New(),
			PrincipalID:   principalID,
			PrincipalType: principalType,
			ResourceType:  p.Resource,
			Operation:     p.Operation,
			Effect:        model.PolicyEffectAllow,
			VaultID:       &v,
			AssignmentID:  &a,
			CreatedAt:     now,
		})
	}
	return policies, nil
}
