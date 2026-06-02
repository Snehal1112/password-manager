package api

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// InitVault initializes the routes for vault management.
// Management routes use the {name} path variable rather than {vault_name} so
// that VaultResolutionMiddleware falls back to the default vault and does not
// interfere with managing a disabled or soft-deleted vault.
// It sets up the following endpoints:
//   - POST   /vaults         : Create a new vault.
//   - GET    /vaults         : List vaults (honors ?include_deleted=true).
//   - GET    /vaults/{name}  : Get a vault by name.
//   - PATCH  /vaults/{name}  : Update a vault.
//   - DELETE /vaults/{name}  : Soft-delete a vault.
func (api *API) InitVault() {
	v := api.BaseRoutes.Vaults

	v.Handle("", ApiSessionRequired(api.App, createVault)).Methods("POST")
	v.Handle("", ApiSessionRequired(api.App, listVaults)).Methods("GET")
	v.Handle("/{name}", ApiSessionRequired(api.App, getVault)).Methods("GET")
	v.Handle("/{name}", ApiSessionRequired(api.App, updateVault)).Methods("PATCH")
	v.Handle("/{name}", ApiSessionRequired(api.App, deleteVault)).Methods("DELETE")
}

// vaultSvc returns the vault service, setting an internal error if unavailable.
func (c *Context) vaultSvc() vaultServices.VaultService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetVaultService()
}

// createVault handles the creation of a new vault.
func createVault(c *Context, w http.ResponseWriter, r *http.Request) {
	req, err := model.CreateVaultRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	// Get the creator user ID from JWT claims.
	userIDStr, ok := c.Claims["user_id"].(string)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.SetInvalidParam("user_id")
		return
	}

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	vault, err := svc.CreateVault(r.Context(), *req, userID)
	if err != nil {
		// Validation and duplicate failures are client errors.
		c.SetInvalidParam(err.Error())
		return
	}

	response := vault.ToResponse()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(response.ToJson()))

	c.Logger.Printf("User %s created vault %s", userIDStr, vault.Name)
}

// listVaults handles the request to list vaults, optionally including soft-deleted ones.
func listVaults(c *Context, w http.ResponseWriter, r *http.Request) {
	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	includeDeleted := r.URL.Query().Get("include_deleted") == "true"

	vaults, err := svc.ListVaults(r.Context(), includeDeleted)
	if err != nil {
		c.SetInternalError(err)
		return
	}

	responses := make([]model.VaultResponse, len(vaults))
	for i := range vaults {
		responses[i] = vaults[i].ToResponse()
	}

	response := model.ListVaultsResponse{
		Vaults: responses,
		Total:  len(responses),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}

// getVault handles the request to retrieve a single vault by name.
func getVault(c *Context, w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	vault, err := svc.GetVault(r.Context(), name)
	if err != nil {
		c.SetNotFound("vault")
		return
	}

	response := vault.ToResponse()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}

// updateVault handles the request to update a vault by name.
func updateVault(c *Context, w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	req, err := model.UpdateVaultRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	// Read the acting user ID from claims. Absence is not fatal here; we fall
	// back to the nil UUID so callers without a parseable claim still succeed.
	var updatedBy uuid.UUID
	if userIDStr, ok := c.Claims["user_id"].(string); ok {
		if parsed, perr := uuid.Parse(userIDStr); perr == nil {
			updatedBy = parsed
		}
	}

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	vault, err := svc.UpdateVault(r.Context(), name, *req, updatedBy)
	if err != nil {
		// The not-found sentinel maps to 404; validation and other failures are
		// client errors.
		if errors.Is(err, vaultServices.ErrVaultNotFound) {
			c.SetNotFound("vault")
			return
		}
		c.SetInvalidParam(err.Error())
		return
	}

	response := vault.ToResponse()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))

	c.Logger.Printf("Vault %s updated", name)
}

// deleteVault handles the soft-delete of a vault by name.
func deleteVault(c *Context, w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	if err := svc.DeleteVault(r.Context(), name); err != nil {
		// The not-found sentinel maps to 404; all other failures (such as the
		// refusal to delete the default vault) are client errors.
		if errors.Is(err, vaultServices.ErrVaultNotFound) {
			c.SetNotFound("vault")
			return
		}
		c.SetInvalidParam(err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)

	c.Logger.Printf("Vault %s deleted", name)
}
