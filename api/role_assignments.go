package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	authzServices "rocketvault/internal/services/authorization"
	"rocketvault/model"
)

// InitRoleAssignments registers vault-scoped role-assignment routes.
func (api *API) InitRoleAssignments() {
	r := api.BaseRoutes.RoleAssignments
	one := api.BaseRoutes.RoleAssignment
	r.Handle("", ApiSessionRequired(api.App, listRoleAssignments)).Methods("GET")
	r.Handle("", ApiSessionRequired(api.App, createRoleAssignment)).Methods("POST")
	one.Handle("", ApiSessionRequired(api.App, getRoleAssignment)).Methods("GET")
	one.Handle("", ApiSessionRequired(api.App, deleteRoleAssignment)).Methods("DELETE")
}

// buildRoleAssignmentResponse maps a RoleAssignment onto its enriched API
// representation: vault name from the URL, principal username resolved via
// the user service, and the policy count implied by the role bundle.
// Username resolution failure is non-fatal (the field is omitempty) so a
// stale/deleted principal doesn't block the response.
func buildRoleAssignmentResponse(c *Context, r *http.Request, ra *model.RoleAssignment) model.RoleAssignmentResponse {
	resp := ra.ToResponse()
	resp.VaultName = c.Params.VaultName
	if userSvc := c.App.ServiceContainer.GetUserService(); userSvc != nil {
		if user, err := userSvc.GetUser(r.Context(), ra.PrincipalID); err == nil && user != nil {
			resp.PrincipalUsername = user.Username
		}
	}
	if perms, err := authzServices.RolePermissions(ra.Role); err == nil {
		resp.ExpandedPolicyCount = len(perms)
	}
	return resp
}

// callerIdentity extracts the acting principal's account role and user ID
// from the session claims. Returns ok=false if either is missing or
// malformed, in which case the caller must treat this as an internal error,
// not a permission denial — a malformed claim is a bug, not a 403.
func callerIdentity(c *Context) (role string, principalID uuid.UUID, ok bool) {
	principalID, err := uuid.Parse(c.Claims.UserID)
	return c.Claims.Role, principalID, err == nil
}

// createRoleAssignment grants a built-in role to a principal within a vault.
// POST /vaults/{vault_name}/role-assignments
func createRoleAssignment(c *Context, w http.ResponseWriter, r *http.Request) {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return
	}
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	role, callerID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	if !authzServices.CanManageRoleAssignments(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(),
		c.App.ServiceContainer.GetRoleAssignmentService(), callerID, vaultID, true) {
		c.SetPermissionError("admin, vaults/manage, or Key Vault Data Access Administrator required")
		return
	}

	req, err := model.AssignRoleRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}
	if req.Principal == "" || req.Role == "" {
		c.SetInvalidParam("principal and role are required")
		return
	}
	pType := model.PrincipalType(req.PrincipalType)
	if pType == "" {
		pType = model.PrincipalTypeUser
	}

	svc := c.App.ServiceContainer.GetRoleAssignmentService()
	ra, err := svc.AssignRole(r.Context(), authzServices.AssignRoleInput{
		Principal:     req.Principal,
		PrincipalType: pType,
		Role:          req.Role,
		VaultID:       vaultID,
		CreatedBy:     callerID,
	})
	if err != nil {
		switch {
		case errors.Is(err, authzServices.ErrInvalidRole):
			c.SetInvalidParam("role")
		case errors.Is(err, authzServices.ErrPrincipalNotFound):
			c.SetNotFound("principal")
		default:
			c.SetInternalError(err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(buildRoleAssignmentResponse(c, r, ra)) //nolint:errcheck,gosec
}

// listRoleAssignments returns all role assignments scoped to a vault.
// GET /vaults/{vault_name}/role-assignments
//
// Reading assignments discloses who holds which role in the vault (including
// principal usernames), so it is gated exactly like revoking them: the same
// CanManageRoleAssignments check with write=false.
func listRoleAssignments(c *Context, w http.ResponseWriter, r *http.Request) {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return
	}
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	role, callerID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	if !authzServices.CanManageRoleAssignments(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(),
		c.App.ServiceContainer.GetRoleAssignmentService(), callerID, vaultID, false) {
		c.SetPermissionError("admin, vaults/manage, or Key Vault Data Access Administrator required")
		return
	}
	svc := c.App.ServiceContainer.GetRoleAssignmentService()
	list, err := svc.ListAssignments(r.Context(), vaultID)
	if err != nil {
		c.SetInternalError(err)
		return
	}
	responses := make([]model.RoleAssignmentResponse, 0, len(list))
	for _, ra := range list {
		responses = append(responses, buildRoleAssignmentResponse(c, r, ra))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(model.ListRoleAssignmentsResponse{RoleAssignments: responses, Total: len(responses)}) //nolint:errcheck,gosec
}

// getRoleAssignment returns a single role assignment by id within a vault.
// GET /vaults/{vault_name}/role-assignments/{assignment_id}
//
// Gated identically to listRoleAssignments: reading a single assignment leaks
// the same information as reading them all.
func getRoleAssignment(c *Context, w http.ResponseWriter, r *http.Request) {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return
	}
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	role, callerID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	if !authzServices.CanManageRoleAssignments(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(),
		c.App.ServiceContainer.GetRoleAssignmentService(), callerID, vaultID, false) {
		c.SetPermissionError("admin, vaults/manage, or Key Vault Data Access Administrator required")
		return
	}
	id, err := uuid.Parse(c.Params.AssignmentID)
	if err != nil {
		c.SetInvalidParam("assignment_id")
		return
	}
	svc := c.App.ServiceContainer.GetRoleAssignmentService()
	list, err := svc.ListAssignments(r.Context(), vaultID)
	if err != nil {
		c.SetInternalError(err)
		return
	}
	for _, ra := range list {
		if ra.ID == id {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(buildRoleAssignmentResponse(c, r, ra)) //nolint:errcheck,gosec
			return
		}
	}
	c.SetNotFound("role assignment")
}

// deleteRoleAssignment revokes a role assignment within a vault.
// DELETE /vaults/{vault_name}/role-assignments/{assignment_id}
func deleteRoleAssignment(c *Context, w http.ResponseWriter, r *http.Request) {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return
	}
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	role, callerID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	if !authzServices.CanManageRoleAssignments(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(),
		c.App.ServiceContainer.GetRoleAssignmentService(), callerID, vaultID, false) {
		c.SetPermissionError("admin, vaults/manage, or Key Vault Data Access Administrator required")
		return
	}
	id, err := uuid.Parse(c.Params.AssignmentID)
	if err != nil {
		c.SetInvalidParam("assignment_id")
		return
	}
	svc := c.App.ServiceContainer.GetRoleAssignmentService()
	if err := svc.RevokeAssignment(r.Context(), id, vaultID); err != nil {
		if errors.Is(err, authzServices.ErrAssignmentNotFound) {
			c.SetNotFound("role assignment")
			return
		}
		c.SetInternalError(err)
		return
	}
	ReturnStatusOK(w)
}
