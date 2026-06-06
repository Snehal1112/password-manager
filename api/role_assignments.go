package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"rocketvault/common"
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

// requireVaultManage gates assignment management to global admins or vault managers.
func requireVaultManage(c *Context, r *http.Request, vaultID uuid.UUID) bool {
	role, _ := c.Claims["role"].(string)
	if common.HasRequiredRole(role, string(model.RoleAdmin)) {
		return true
	}
	userIDStr, _ := c.Claims["user_id"].(string)
	pid, err := uuid.Parse(userIDStr)
	if err != nil {
		return false
	}
	dec, err := c.App.ServiceContainer.GetAccessPolicyService().
		CheckAccess(r.Context(), pid, model.PolicyResourceVaults, model.OpManage, vaultID)
	if err != nil {
		return false
	}
	return dec == authzServices.AccessAllowed
}

// createRoleAssignment grants a built-in role to a principal within a vault.
// POST /vaults/{vault_name}/role-assignments
func createRoleAssignment(c *Context, w http.ResponseWriter, r *http.Request) {
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	if !requireVaultManage(c, r, vaultID) {
		c.SetPermissionError("admin or vaults/manage required")
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

	callerIDStr, _ := c.Claims["user_id"].(string)
	callerID, _ := uuid.Parse(callerIDStr)

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
	json.NewEncoder(w).Encode(ra)
}

// listRoleAssignments returns all role assignments scoped to a vault.
// GET /vaults/{vault_name}/role-assignments
func listRoleAssignments(c *Context, w http.ResponseWriter, r *http.Request) {
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	svc := c.App.ServiceContainer.GetRoleAssignmentService()
	list, err := svc.ListAssignments(r.Context(), vaultID)
	if err != nil {
		c.SetInternalError(err)
		return
	}
	if list == nil {
		list = []*model.RoleAssignment{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"role_assignments": list, "total": len(list)})
}

// getRoleAssignment returns a single role assignment by id within a vault.
// GET /vaults/{vault_name}/role-assignments/{assignment_id}
func getRoleAssignment(c *Context, w http.ResponseWriter, r *http.Request) {
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
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
			json.NewEncoder(w).Encode(ra)
			return
		}
	}
	c.SetNotFound("role assignment")
}

// deleteRoleAssignment revokes a role assignment within a vault.
// DELETE /vaults/{vault_name}/role-assignments/{assignment_id}
func deleteRoleAssignment(c *Context, w http.ResponseWriter, r *http.Request) {
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	if !requireVaultManage(c, r, vaultID) {
		c.SetPermissionError("admin or vaults/manage required")
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
