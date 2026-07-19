// Package api — authorization tests for vault.go management handlers.
package api

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	authzServices "rocketvault/internal/services/authorization"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// --- buildAuthzVaultAPI ---

// buildAuthzVaultAPI wires a vault API whose access-policy decisions are driven by
// the given mock, and whose coarse RBAC is permissive so the per-vault gate is the
// only source of 403. It seeds a single target vault "prod" and returns its ID.
func buildAuthzVaultAPI(policySvc authzServices.AccessPolicyService) (*API, uuid.UUID) {
	repo := newVaultFakeRepo()
	svc := vaultServices.NewVaultService(repo, vaultNoopCascade{}, nil)

	id := uuid.New()
	repo.byName["prod"] = &model.Vault{ID: id, Name: "prod", Enabled: true}
	repo.byID[id.String()] = repo.byName["prod"]

	container := &vaultSvcTestContainer{
		vaultSvc:  svc,
		policySvc: policySvc,
		rbacSvc:   permissiveRBAC{},
	}
	return newVaultTestAPIWithContainer(container), id
}

// --- Authorization Tests ---

// TestGetVault_ForbiddenWhenNotScopedToTargetVault proves that a non-admin whose
// vaults:manage grant does NOT cover the target vault gets 403, not 200.
func TestGetVault_ForbiddenWhenNotScopedToTargetVault(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	// No policy covers prod's ID -> AccessFallback -> requireVaultManage denies.
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, mock.Anything).
		Return(authzServices.AccessFallback, nil)

	api, _ := buildAuthzVaultAPI(policySvc)

	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodGet, "/api/v1/vaults/prod", nil)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestGetVault_AllowedWhenScopedToTargetVault proves that a matching vaults:manage
// grant on the target vault still returns 200.
func TestGetVault_AllowedWhenScopedToTargetVault(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	api, id := buildAuthzVaultAPI(policySvc)
	policySvc.On("CheckAccess", mock.Anything, mock.Anything,
		model.PolicyResourceVaults, model.OpManage, id).
		Return(authzServices.AccessAllowed, nil)

	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodGet, "/api/v1/vaults/prod", nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestGetVault_NotFoundBeforeForbidden proves a missing vault yields 404 even for a
// principal that would otherwise be denied (not-found precedes forbidden).
func TestGetVault_NotFoundBeforeForbidden(t *testing.T) {
	policySvc := &mockAccessPolicyService{}
	policySvc.On("CheckAccess", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(authzServices.AccessFallback, nil)
	api, _ := buildAuthzVaultAPI(policySvc)

	w := doVaultRequestAs(api, string(model.RoleUser), http.MethodGet, "/api/v1/vaults/ghost", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
