package authorization

import (
	"testing"

	"rocketvault/internal/logging"
	"rocketvault/model"
)

// TestValidateEndpointAccess_DataPlaneRoutesDelegate asserts that vault
// data-plane routes no longer consult the caller's global role. They are
// authorized by PolicyMiddleware against the caller's role assignments in the
// resolved vault, so the global RBAC layer must not second-guess that decision:
// a Key Vault Crypto Officer whose global role is "user" must be able to create
// a key in the vault they hold the role in.
func TestValidateEndpointAccess_DataPlaneRoutesDelegate(t *testing.T) {
	svc := NewRBACService(logging.InitLogger())

	paths := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/vaults/prod/secrets"},
		{"DELETE", "/api/v1/vaults/prod/secrets/abc"},
		{"PUT", "/api/v1/vaults/prod/keys/abc"},
		{"POST", "/api/v1/vaults/prod/keys"},
		{"DELETE", "/api/v1/vaults/prod/certificates/abc"},
		{"POST", "/api/v1/vaults/prod/keys/abc/sign"},
		{"DELETE", "/api/v1/vaults/prod/deleted/secrets/abc/purge"},
		{"POST", "/api/v1/secrets"},
		{"GET", "/api/v1/secrets/abc"},
		{"POST", "/api/v1/keys"},
		{"DELETE", "/api/v1/certificates/abc"},
	}
	roles := []string{
		model.RoleUser, model.RoleServiceAccount, model.RoleSecretsManager,
		model.RoleCryptoManager, model.RoleCertificateManager, model.RoleAdmin,
	}

	for _, p := range paths {
		for _, role := range roles {
			t.Run(role+" "+p.method+" "+p.path, func(t *testing.T) {
				if err := svc.ValidateEndpointAccess([]string{role}, p.method, p.path); err != nil {
					t.Fatalf("data-plane routes must not be gated by the global role, got %v", err)
				}
			})
		}
	}
}

// TestMapEndpointToPermission_DataPlaneReturnsEmpty pins the mapping directly,
// so a future edit cannot reintroduce a global permission on a data-plane route
// without failing here.
func TestMapEndpointToPermission_DataPlaneReturnsEmpty(t *testing.T) {
	svc := NewRBACService(logging.InitLogger()).(*rbacService)
	for _, c := range []struct{ method, path string }{
		{"POST", "/api/v1/vaults/prod/secrets"},
		{"GET", "/api/v1/vaults/prod/keys"},
		{"PUT", "/api/v1/certificates/abc"},
		{"GET", "/api/v1/deleted/secrets"},
	} {
		if got := svc.mapEndpointToPermission(c.method, c.path); got != "" {
			t.Fatalf("mapEndpointToPermission(%s, %s) = %q, want empty", c.method, c.path, got)
		}
	}
}

// TestMapEndpointToPermission_VaultProvisioningGrantsReturnsEmpty pins that
// "/vault-provisioning-grants" routes are NOT swallowed by the "vaults"
// prefix check below -- "vault-" differs from "vaults" at the 6th character.
// These routes are admin-only and deliberately non-delegable (see
// api/vault_provisioning_grants.go's requireGrantAdmin); mapEndpointToPermission
// returning "" here is what lets the request reach that handler-level gate
// at all (ValidateEndpointAccess short-circuits to nil on an empty
// permission). Had the "vaults" prefix check matched here instead -- e.g.
// after a future rename to strings.HasPrefix(path, "vault") -- the
// authorization decision would still (currently) come out the same by
// accident, since vault-management routes also return "", but the mapping
// itself would be silently wrong. This pins the mapping directly, the same
// way TestMapEndpointToPermission_DataPlaneReturnsEmpty pins the data-plane
// mapping.
func TestMapEndpointToPermission_VaultProvisioningGrantsReturnsEmpty(t *testing.T) {
	svc := NewRBACService(logging.InitLogger()).(*rbacService)
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/vault-provisioning-grants"},
		{"PUT", "/api/v1/vault-provisioning-grants/abc"},
		{"DELETE", "/api/v1/vault-provisioning-grants/abc"},
	} {
		if got := svc.mapEndpointToPermission(c.method, c.path); got != "" {
			t.Fatalf("mapEndpointToPermission(%s, %s) = %q, want empty", c.method, c.path, got)
		}
	}
}

// TestValidateEndpointAccess_VaultManagementRoutes verifies that vault
// management routes (/api/v1/vaults[/{name}]) are NOT gated by the global
// RBAC layer for any role, admin or not. This inverts the pre-2026-08-11
// behavior: mapEndpointToPermission used to require the admin-only
// vaults:manage permission here, which made every handler-level
// CanManageVault check (api/vault.go) unreachable for non-admins in
// production — see
// docs/superpowers/specs/2026-08-11-azure-role-parity-and-vault-authz-fix-design.md,
// "Root cause". Vault management is now authorized entirely by the
// handler's own per-vault check.
func TestValidateEndpointAccess_VaultManagementRoutes(t *testing.T) {
	svc := NewRBACService(logging.InitLogger())

	cases := []struct {
		name   string
		role   string
		method string
		path   string
	}{
		{"user reaches create vault gate", model.RoleUser, "POST", "/api/v1/vaults"},
		{"user reaches delete vault gate", model.RoleUser, "DELETE", "/api/v1/vaults/prod"},
		{"user reaches update vault gate", model.RoleUser, "PATCH", "/api/v1/vaults/prod"},
		{"service-account reaches delete vault gate", model.RoleServiceAccount, "DELETE", "/api/v1/vaults/prod"},
		{"secrets-manager reaches delete vault gate", model.RoleSecretsManager, "DELETE", "/api/v1/vaults/prod"},
		{"admin reaches create vault gate", model.RoleAdmin, "POST", "/api/v1/vaults"},
		{"admin reaches delete vault gate", model.RoleAdmin, "DELETE", "/api/v1/vaults/prod"},
		{"admin reaches get vault gate", model.RoleAdmin, "GET", "/api/v1/vaults/prod"},
		{"admin reaches list vaults gate", model.RoleAdmin, "GET", "/api/v1/vaults"},
		{"non-admin reaches purge vault gate", model.RoleUser, "DELETE", "/api/v1/vaults/prod/purge"},
		{"non-admin reaches role-assignment create gate", model.RoleUser, "POST", "/api/v1/vaults/prod/role-assignments"},
		{"non-admin reaches role-assignment revoke gate", model.RoleUser, "DELETE", "/api/v1/vaults/prod/role-assignments/abc"},
		{"non-admin reaches role-assignment list gate", model.RoleUser, "GET", "/api/v1/vaults/prod/role-assignments"},
		{"non-admin reaches role-assignment get gate", model.RoleUser, "GET", "/api/v1/vaults/prod/role-assignments/abc"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := svc.ValidateEndpointAccess([]string{c.role}, c.method, c.path); err != nil {
				t.Fatalf("ValidateEndpointAccess(%s, %s, %s) = %v, want nil — the global layer must defer entirely to the handler's own check", c.role, c.method, c.path, err)
			}
		})
	}

	// User management keeps its global permissions; it is not a vault data plane.
	if err := svc.ValidateEndpointAccess([]string{model.RoleUser}, "POST", "/api/v1/users"); err == nil {
		t.Fatal("user creation must still require the global users:create permission")
	}
}

// TestValidateEndpointAccess_MultiRoleCallerGranted asserts that a caller
// holding multiple roles is authorized if ANY of those roles grants the
// required permission. Before this fix, ValidateEndpointAccess took a single
// role string and HasPermission did an exact map lookup keyed by that one
// string — a multi-role caller was always "unknown role," denied outright,
// even when one of their roles individually would have been granted.
//
// The production role-permission table has no HTTP-reachable endpoint where
// this actually bites: every data-plane route (secrets/keys/certificates)
// bypasses global RBAC entirely (see mapEndpointToPermission), and /users is
// the only route still gated, granted to "admin" alone. So this test builds
// an rbacService directly with a small custom rolePermissions map — same
// mechanism NewRBACService wires up, just with test-local grants — to
// isolate ValidateEndpointAccess's role-loop from that production-table
// constraint.
func TestValidateEndpointAccess_MultiRoleCallerGranted(t *testing.T) {
	svc := &rbacService{
		rolePermissions: map[string][]Permission{
			model.RoleUser:           {PermissionReadUser},
			model.RoleSecretsManager: {PermissionCreateUser},
		},
		logger: logging.InitLogger(),
	}

	// "user" alone lacks users:create; "secrets_manager" alone has it.
	if svc.HasPermission(model.RoleUser, PermissionCreateUser) {
		t.Fatal("user role must not have users:create in this test setup")
	}
	if !svc.HasPermission(model.RoleSecretsManager, PermissionCreateUser) {
		t.Fatal("secrets_manager role must have users:create in this test setup")
	}

	// A caller holding both roles must be granted: this is the exact bug
	// class this task exists to fix.
	roles := []string{model.RoleUser, model.RoleSecretsManager}
	if err := svc.ValidateEndpointAccess(roles, "POST", "/api/v1/users"); err != nil {
		t.Fatalf("multi-role caller should be granted access via secrets_manager's grant, got %v", err)
	}
}

// TestVaultManagePermission_OnlyAdmin verifies the vaults:manage permission is
// granted exclusively to the admin role.
func TestVaultManagePermission_OnlyAdmin(t *testing.T) {
	svc := NewRBACService(logging.InitLogger())

	if !svc.HasPermission(model.RoleAdmin, PermissionManageVaults) {
		t.Fatal("admin must have vaults:manage permission")
	}
	for _, role := range []string{
		model.RoleUser, model.RoleServiceAccount, model.RoleSecretsManager,
		model.RoleCryptoManager, model.RoleCertificateManager,
	} {
		if svc.HasPermission(role, PermissionManageVaults) {
			t.Fatalf("role %s must NOT have vaults:manage permission", role)
		}
	}
}
