package cliclient

import (
	"rocketvault/internal/vaultapi"
	"rocketvault/model"
)

// RoleAssignmentFromAPI converts the API client's role assignment into the
// model type the CLI's output code already formats, so remote and local
// output are identical.
//
// Returned by value: the struct is small, and a nil pointer would be a second
// failure mode for a conversion that cannot fail. Later converters in this
// file (SecretFromAPI, KeyFromAPI, ...) should follow the same form.
//
// VaultID is left empty: the API returns vault_name and the CLI addresses
// vaults by name in remote mode. See unmappedRoleAssignmentFields in the
// test for the full accounting.
func RoleAssignmentFromAPI(r *vaultapi.RoleAssignment) model.RoleAssignmentResponse {
	if r == nil {
		return model.RoleAssignmentResponse{}
	}
	return model.RoleAssignmentResponse{
		ID:                r.ID.String(),
		PrincipalID:       r.PrincipalID.String(),
		PrincipalUsername: r.PrincipalUsername,
		PrincipalType:     r.PrincipalType,
		Role:              r.Role,
		VaultName:         r.VaultName,
		CreatedAt:         r.CreatedAt,
	}
}
