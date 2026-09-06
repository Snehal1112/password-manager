// Package api — provisioning-grant management. A grant is a bounded right to
// create vaults, the delegated alternative to a global vaults:manage policy
// (which additionally confers authority over every vault that already
// exists).
//
// A grant is not scoped to any vault -- there is no vault yet when one is
// issued -- so these are instance-level routes rather than sub-resources of
// /vaults/{name}, mirroring /access-policies.
//
//   - PUT    /vault-provisioning-grants/{principal_id} : issue or re-quota.
//   - DELETE /vault-provisioning-grants/{principal_id} : revoke.
//   - GET    /vault-provisioning-grants                : list all.
//
// This tier is admin-only and deliberately non-delegable: unlike role
// assignments, where a Key Vault Data Access Administrator may delegate
// within an allow-list, there is no delegated path here at all. A principal
// able to amend grants could raise its own quota, and the bound the grant
// exists to impose would be decorative. See requireGrantAdmin.
//
// These routes resolve no vault of their own, so VaultResolutionMiddleware
// falls back to the default vault, and VaultRateLimitMiddleware correctly
// counts requests here against the default vault's budget. That is intended
// -- a grant belongs to no vault -- not a bug to "fix"; see
// internal/middleware/vault_rate_limit.go.
package api

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"rocketvault/common"
	"rocketvault/internal/services/provisioning"
	"rocketvault/model"
)

// InitVaultProvisioningGrants registers provisioning-grant routes.
func (api *API) InitVaultProvisioningGrants() {
	r := api.BaseRoutes.VaultProvisioningGrants
	r.Handle("", ApiSessionRequired(api.App, listVaultProvisioningGrants)).Methods("GET")
	r.Handle("/{principal_id}", ApiSessionRequired(api.App, upsertVaultProvisioningGrant)).Methods("PUT")
	r.Handle("/{principal_id}", ApiSessionRequired(api.App, deleteVaultProvisioningGrant)).Methods("DELETE")
}

// IssueGrantRequest is the body of a PUT. The principal comes from the path,
// so it is deliberately absent here -- accepting it in both places would
// invite them to disagree.
type IssueGrantRequest struct {
	Quota int `json:"quota"`
}

// requireGrantAdmin gates provisioning-grant management to the global admin
// role. This tier is deliberately non-delegable: a principal able to amend
// grants could raise its own quota, and the bound the grant exists to impose
// would be decorative. Mirrors requireAccessPolicyAdmin in
// api/access_policies.go.
func requireGrantAdmin(c *Context) bool {
	if !common.HasAnyRole(c.Claims.Roles, model.RoleAdmin) {
		c.SetPermissionError("admin role required to manage vault provisioning grants")
		return false
	}
	return true
}

// upsertVaultProvisioningGrant issues a new grant, or re-quotas an existing
// one -- principal_id is UNIQUE, so a second PUT for the same principal
// changes the quota rather than creating a second right.
// PUT /vault-provisioning-grants/{principal_id}
func upsertVaultProvisioningGrant(c *Context, w http.ResponseWriter, r *http.Request) {
	if !requireGrantAdmin(c) {
		return
	}
	principalID, ok := resourceID(c, c.Params.PrincipalID, "principal_id")
	if !ok {
		return
	}
	req, bodyOK := decodeBody[IssueGrantRequest](c, r)
	if !bodyOK {
		return
	}
	issuerID, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		c.SetInvalidParam("caller identity")
		return
	}

	svc := c.App.ServiceContainer.GetGrantService()
	// This pre-read exists only to choose the response status (201 created vs
	// 200 re-quotaed) below; its value is never used, since the response body
	// comes from IssueGrant's own return. ErrGrantNotFound is the only
	// expected outcome for a genuinely new principal -- any other error means
	// the lookup itself failed (e.g. a DB outage) and must surface as a 500,
	// not be silently read as "this is a create".
	_, existsErr := svc.GetGrant(r.Context(), principalID)
	if existsErr != nil && !errors.Is(existsErr, provisioning.ErrGrantNotFound) {
		c.SetInternalError(existsErr)
		return
	}
	existed := existsErr == nil

	g, err := svc.IssueGrant(r.Context(), principalID, req.Quota, issuerID)
	if errors.Is(err, model.ErrInvalidPrincipal) {
		c.SetInvalidParam("principal_id")
		return
	}
	if errors.Is(err, model.ErrInvalidQuota) {
		c.SetInvalidParam("quota")
		return
	}
	if err != nil {
		c.SetInternalError(err)
		return
	}

	status := http.StatusCreated
	if existed {
		status = http.StatusOK // an existing grant was re-quotaed, not created
	}
	writeJSONStatus(w, status, g)
}

// deleteVaultProvisioningGrant revokes a principal's provisioning grant.
// Revocation does NOT cascade: it stops future vault creation only, and
// deliberately leaves the principal's existing vaults, and its rights over
// them, intact. Cascading would let one DELETE strip a customer's access to
// vaults it already has -- removing that is a separate operator action.
// DELETE /vault-provisioning-grants/{principal_id}
func deleteVaultProvisioningGrant(c *Context, w http.ResponseWriter, r *http.Request) {
	if !requireGrantAdmin(c) {
		return
	}
	principalID, ok := resourceID(c, c.Params.PrincipalID, "principal_id")
	if !ok {
		return
	}
	revokedBy, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		c.SetInvalidParam("caller identity")
		return
	}
	if err := c.App.ServiceContainer.GetGrantService().RevokeGrant(r.Context(), principalID, revokedBy); err != nil {
		c.SetInternalError(err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listVaultProvisioningGrants returns every provisioning grant.
// GET /vault-provisioning-grants
func listVaultProvisioningGrants(c *Context, w http.ResponseWriter, r *http.Request) {
	if !requireGrantAdmin(c) {
		return
	}
	grants, err := c.App.ServiceContainer.GetGrantService().ListGrants(r.Context())
	if err != nil {
		c.SetInternalError(err)
		return
	}
	// A nil slice marshals to JSON null, and a client iterating the response
	// would fault. listSecrets (api/secrets.go) guards the same way.
	if grants == nil {
		grants = []*model.VaultProvisioningGrant{}
	}
	writeJSON(w, grants)
}
