package api

import (
"encoding/json"
"net/http"
"time"

"github.com/google/uuid"
"github.com/gorilla/mux"

"rocketvault/common"
"rocketvault/internal/domain"
)

// listAccessPolicies returns all access policies (admin operation).
// GET /access-policies
func listAccessPolicies(c *Context, w http.ResponseWriter, r *http.Request) {
	svc := c.App.ServiceContainer.GetAccessPolicyService()
	policies, err := svc.ListPolicies(r.Context())
	if err != nil {
		c.Err = common.NewAppError("listAccessPolicies", "Failed to list access policies", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	if policies == nil {
		policies = []*domain.AccessPolicy{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
"access_policies": policies,
"total":           len(policies),
})
}

// createAccessPolicy creates a new access policy.
// POST /access-policies
func createAccessPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	var req struct {
		PrincipalID   string `json:"principal_id"`
		PrincipalType string `json:"principal_type"`
		ResourceType  string `json:"resource_type"`
		Operation     string `json:"operation"`
		Effect        string `json:"effect"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("createAccessPolicy", "Invalid request body", nil, err.Error(), http.StatusBadRequest)
		return
	}

	principalID, err := uuid.Parse(req.PrincipalID)
	if err != nil {
		c.Err = common.NewAppError("createAccessPolicy", "Invalid principal_id", nil, err.Error(), http.StatusBadRequest)
		return
	}
	if req.ResourceType == "" || req.Operation == "" || req.Effect == "" || req.PrincipalType == "" {
		c.Err = common.NewAppError("createAccessPolicy", "Missing required fields", nil, "", http.StatusBadRequest)
		return
	}

	policy := &domain.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   principalID,
		PrincipalType: domain.PrincipalType(req.PrincipalType),
		ResourceType:  domain.PolicyResourceType(req.ResourceType),
		Operation:     domain.PolicyOperation(req.Operation),
		Effect:        domain.PolicyEffect(req.Effect),
		CreatedAt:     time.Now().UTC(),
	}

	svc := c.App.ServiceContainer.GetAccessPolicyService()
	if err := svc.CreatePolicy(r.Context(), policy); err != nil {
		c.Err = common.NewAppError("createAccessPolicy", "Failed to create access policy", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(policy)
}

// getAccessPolicy retrieves a single access policy by ID.
// GET /access-policies/{id}
func getAccessPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	id, appErr := resourceIDFromVars(c, r, "getAccessPolicy")
	if appErr != nil {
		c.Err = appErr
		return
	}

	svc := c.App.ServiceContainer.GetAccessPolicyService()
	policy, err := svc.GetPolicy(r.Context(), id)
	if err != nil {
		c.Err = common.NewAppError("getAccessPolicy", "Access policy not found", nil, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

// updateAccessPolicy updates the effect of an existing access policy.
// PUT /access-policies/{id}
func updateAccessPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	id, appErr := resourceIDFromVars(c, r, "updateAccessPolicy")
	if appErr != nil {
		c.Err = appErr
		return
	}

	var req struct {
		Effect string `json:"effect"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("updateAccessPolicy", "Invalid request body", nil, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Effect == "" {
		c.Err = common.NewAppError("updateAccessPolicy", "Missing required field: effect", nil, "", http.StatusBadRequest)
		return
	}

	svc := c.App.ServiceContainer.GetAccessPolicyService()
	policy, err := svc.GetPolicy(r.Context(), id)
	if err != nil {
		c.Err = common.NewAppError("updateAccessPolicy", "Access policy not found", nil, err.Error(), http.StatusNotFound)
		return
	}

	policy.Effect = domain.PolicyEffect(req.Effect)
	if err := svc.UpdatePolicy(r.Context(), policy); err != nil {
		c.Err = common.NewAppError("updateAccessPolicy", "Failed to update access policy", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

// deleteAccessPolicy permanently removes an access policy.
// DELETE /access-policies/{id}
func deleteAccessPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	id, appErr := resourceIDFromVars(c, r, "deleteAccessPolicy")
	if appErr != nil {
		c.Err = appErr
		return
	}

	svc := c.App.ServiceContainer.GetAccessPolicyService()
	if err := svc.DeletePolicy(r.Context(), id); err != nil {
		c.Err = common.NewAppError("deleteAccessPolicy", "Failed to delete access policy", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// listAccessPoliciesByPrincipal returns all policies for a given principal UUID.
// GET /access-policies/principal/{principalId}
func listAccessPoliciesByPrincipal(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	principalID, err := uuid.Parse(vars["principalId"])
	if err != nil {
		c.Err = common.NewAppError("listAccessPoliciesByPrincipal", "Invalid principal ID", nil, err.Error(), http.StatusBadRequest)
		return
	}

	svc := c.App.ServiceContainer.GetAccessPolicyService()
	policies, err := svc.ListByPrincipal(r.Context(), principalID)
	if err != nil {
		c.Err = common.NewAppError("listAccessPoliciesByPrincipal", "Failed to list policies for principal", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	if policies == nil {
		policies = []*domain.AccessPolicy{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
"access_policies": policies,
"total":           len(policies),
})
}
