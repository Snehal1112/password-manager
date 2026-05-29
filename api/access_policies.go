package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"rocketvault/model"
)

// InitAccessPolicies registers access policy management routes.
func (api *API) InitAccessPolicies() {
	r := api.BaseRoutes.AccessPolicies
	r.Handle("", ApiSessionRequired(api.App, listAccessPolicies)).Methods("GET")
	r.Handle("", ApiSessionRequired(api.App, createAccessPolicy)).Methods("POST")
	r.Handle("/{policy_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getAccessPolicy)).Methods("GET")
	r.Handle("/{policy_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, updateAccessPolicy)).Methods("PUT")
	r.Handle("/{policy_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, deleteAccessPolicy)).Methods("DELETE")
	r.Handle("/principal/{principal_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, listAccessPoliciesByPrincipal)).Methods("GET")
}

// listAccessPolicies returns all access policies (admin operation).
// GET /access-policies
func listAccessPolicies(c *Context, w http.ResponseWriter, r *http.Request) {
	svc := c.App.ServiceContainer.GetAccessPolicyService()
	policies, err := svc.ListPolicies(r.Context())
	if err != nil {
		c.SetInternalError(err)
		return
	}

	if policies == nil {
		policies = []*model.AccessPolicy{}
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
	var req model.CreateAccessPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}

	principalID, err := uuid.Parse(req.PrincipalID)
	if err != nil {
		c.SetInvalidParam("principal_id")
		return
	}
	if req.ResourceType == "" || req.Operation == "" || req.Effect == "" || req.PrincipalType == "" {
		c.SetInvalidParam("principal_type, resource_type, operation, and effect are required")
		return
	}

	policy := &model.AccessPolicy{
		ID:            uuid.New(),
		PrincipalID:   principalID,
		PrincipalType: model.PrincipalType(req.PrincipalType),
		ResourceType:  model.PolicyResourceType(req.ResourceType),
		Operation:     model.PolicyOperation(req.Operation),
		Effect:        model.PolicyEffect(req.Effect),
		CreatedAt:     time.Now().UTC(),
	}

	// An empty vault_id leaves the policy global; a value scopes it to that vault.
	if req.VaultID != "" {
		vaultID, err := uuid.Parse(req.VaultID)
		if err != nil {
			c.SetInvalidParam("vault_id")
			return
		}
		policy.VaultID = &vaultID
	}

	svc := c.App.ServiceContainer.GetAccessPolicyService()
	if err := svc.CreatePolicy(r.Context(), policy); err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(policy)
}

// getAccessPolicy retrieves a single access policy by ID.
// GET /access-policies/{policy_id}
func getAccessPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(c.Params.PolicyID)
	if err != nil {
		c.SetInvalidParam("policy_id")
		return
	}

	svc := c.App.ServiceContainer.GetAccessPolicyService()
	policy, err := svc.GetPolicy(r.Context(), id)
	if err != nil {
		c.SetNotFound("access policy")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

// updateAccessPolicy updates the effect of an existing access policy.
// PUT /access-policies/{policy_id}
func updateAccessPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(c.Params.PolicyID)
	if err != nil {
		c.SetInvalidParam("policy_id")
		return
	}

	var req struct {
		Effect string `json:"effect"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.SetInvalidParam("request body")
		return
	}
	if req.Effect == "" {
		c.SetInvalidParam("effect is required")
		return
	}

	svc := c.App.ServiceContainer.GetAccessPolicyService()
	policy, err := svc.GetPolicy(r.Context(), id)
	if err != nil {
		c.SetNotFound("access policy")
		return
	}

	policy.Effect = model.PolicyEffect(req.Effect)
	if err := svc.UpdatePolicy(r.Context(), policy); err != nil {
		c.SetInternalError(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

// deleteAccessPolicy permanently removes an access policy.
// DELETE /access-policies/{policy_id}
func deleteAccessPolicy(c *Context, w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(c.Params.PolicyID)
	if err != nil {
		c.SetInvalidParam("policy_id")
		return
	}

	svc := c.App.ServiceContainer.GetAccessPolicyService()
	if err := svc.DeletePolicy(r.Context(), id); err != nil {
		c.SetInternalError(err)
		return
	}

	ReturnStatusOK(w)
}

// listAccessPoliciesByPrincipal returns all policies for a given principal UUID.
// GET /access-policies/principal/{principal_id}
func listAccessPoliciesByPrincipal(c *Context, w http.ResponseWriter, r *http.Request) {
	principalID, err := uuid.Parse(c.Params.PrincipalID)
	if err != nil {
		c.SetInvalidParam("principal_id")
		return
	}

	svc := c.App.ServiceContainer.GetAccessPolicyService()
	policies, err := svc.ListByPrincipal(r.Context(), principalID)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	if policies == nil {
		policies = []*model.AccessPolicy{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_policies": policies,
		"total":           len(policies),
	})
}
