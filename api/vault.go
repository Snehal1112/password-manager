package api

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	authzServices "rocketvault/internal/services/authorization"
	vaultServices "rocketvault/internal/services/vaults"
	"rocketvault/model"
)

// InitVault initializes the routes for vault management.
// Management routes use the {name} path variable rather than {vault_name} so
// that VaultResolutionMiddleware falls back to the default vault and does not
// interfere with managing a disabled or soft-deleted vault. Because that
// fallback means PolicyMiddleware only ever evaluates the default vault for
// these routes, getVault/updateVault/deleteVault each re-resolve the target
// vault by name and call authzServices.CanManageVault against its own ID
// before doing anything observable to the caller — restoring at the handler
// layer the per-vault authorization the middleware layer intentionally skips
// here.
// It sets up the following endpoints:
//   - POST   /vaults         : Create a new vault.
//   - GET    /vaults         : List vaults (honors ?include_deleted=true).
//   - GET    /vaults/{name}  : Get a vault by name.
//   - PATCH  /vaults/{name}  : Update a vault.
//   - DELETE /vaults/{name}  : Soft-delete a vault.
//   - DELETE /vaults/{vault_name}/purge : Permanently purge a vault.
func (api *API) InitVault() {
	v := api.BaseRoutes.Vaults

	v.Handle("", ApiSessionRequired(api.App, createVault)).Methods("POST")
	v.Handle("", ApiSessionRequired(api.App, listVaults)).Methods("GET")
	v.Handle("/{name}", ApiSessionRequired(api.App, getVault)).Methods("GET")
	v.Handle("/{name}", ApiSessionRequired(api.App, updateVault)).Methods("PATCH")
	v.Handle("/{name}", ApiSessionRequired(api.App, deleteVault)).Methods("DELETE")

	// Vault-scoped: resolved via VaultResolutionMiddleware, authorized via
	// PolicyMiddleware's deny-by-default data-plane check, not a handler-level one.
	api.BaseRoutes.VaultScoped.Handle("/purge", ApiSessionRequired(api.App, purgeVault)).Methods("DELETE")
}

// vaultSvc returns the vault service, setting an internal error if unavailable.
func (c *Context) vaultSvc() vaultServices.VaultService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetVaultService()
}

// createVault handles the creation of a new vault. Vault creation has no
// single target vault to check against, so the authorization check uses
// uuid.Nil, matching only a GLOBAL (vault_id: null) vaults:manage allow
// policy — a vault-scoped grant on some other existing vault does not confer
// the ability to create a new one. See the design doc §2 for why this is a
// deliberately narrower interpretation than "any vault-scoped grant".
func createVault(c *Context, w http.ResponseWriter, r *http.Request) {
	role, userID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return
	}
	if !authzServices.CanManageVault(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(), userID, uuid.Nil) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}

	req, err := model.CreateVaultRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
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

	c.Logger.Printf("User %s created vault %s", userID, vault.Name)
}

// listVaults handles the request to list vaults, optionally including
// soft-deleted ones. Like createVault, there is no single target vault, so
// the check uses uuid.Nil (global grant only — see createVault's comment).
func listVaults(c *Context, w http.ResponseWriter, r *http.Request) {
	role, userID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return
	}
	if !authzServices.CanManageVault(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(), userID, uuid.Nil) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}

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
		if errors.Is(err, vaultServices.ErrVaultNotFound) {
			c.SetNotFound("vault")
			return
		}
		c.SetInternalError(err)
		return
	}

	// Authorize against the TARGET vault named in the path. These {name} routes
	// bypass VaultResolutionMiddleware, so PolicyMiddleware only evaluated the
	// default vault; re-check vaults:manage against this vault's own ID.
	role, userID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	if !authzServices.CanManageVault(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(), userID, vault.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}

	response := vault.ToResponse()
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(response.ToJson()))
}

// updateVault handles the request to update a vault by name.
func updateVault(c *Context, w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	// Resolve the target vault first (404), then authorize against it (403), before
	// reading the body or mutating anything. These {name} routes bypass
	// VaultResolutionMiddleware, so the ambient policy check covered only the
	// default vault. UpdateVault re-reads the vault internally; the extra read here
	// is deliberate and cheap.
	target, err := svc.GetVault(r.Context(), name)
	if err != nil {
		if errors.Is(err, vaultServices.ErrVaultNotFound) {
			c.SetNotFound("vault")
			return
		}
		c.SetInternalError(err)
		return
	}
	role, userID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	if !authzServices.CanManageVault(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(), userID, target.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}

	req, err := model.UpdateVaultRequestFromJson(r.Body)
	if err != nil {
		c.SetInvalidParam("request body")
		return
	}

	vault, err := svc.UpdateVault(r.Context(), name, *req, userID)
	if err != nil {
		// The not-found sentinel maps to 404; validation and other failures are
		// client errors. GetVault above already covers the common not-found case;
		// this branch remains as defense in depth against a concurrent delete.
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

	// Resolve the target (404) and authorize (403) before deleting. The default
	// vault resolves successfully here; the "cannot delete the default vault"
	// refusal is still enforced by DeleteVault below and surfaces as a 400.
	target, err := svc.GetVault(r.Context(), name)
	if err != nil {
		if errors.Is(err, vaultServices.ErrVaultNotFound) {
			c.SetNotFound("vault")
			return
		}
		c.SetInternalError(err)
		return
	}
	role, userID, ok := callerIdentity(c)
	if !ok {
		c.SetInternalError(nil)
		return
	}
	_ = userID // not needed by DeleteVault; identity is only used for the check above
	if !authzServices.CanManageVault(r.Context(), role, c.App.ServiceContainer.GetAccessPolicyService(), userID, target.ID) {
		c.SetPermissionError("admin or vaults/manage required")
		return
	}

	if err := svc.DeleteVault(r.Context(), name); err != nil {
		// The not-found sentinel maps to 404; the protected-vault refusal is a
		// client error (400). Anything else (a transaction/DB failure) is an
		// internal error (500) -- it must not be reported as if the caller did
		// something wrong.
		if errors.Is(err, vaultServices.ErrVaultNotFound) {
			c.SetNotFound("vault")
			return
		}
		if errors.Is(err, vaultServices.ErrDefaultVaultProtected) {
			c.SetInvalidParam(err.Error())
			return
		}
		c.SetInternalError(err)
		return
	}

	w.WriteHeader(http.StatusNoContent)

	c.Logger.Printf("Vault %s deleted", name)
}

// purgeVault permanently removes a vault. Registered on the vault-scoped
// router (/vaults/{vault_name}/purge), so VaultResolutionMiddleware resolves
// the target vault and PolicyMiddleware's deny-by-default check (RouteVaultData,
// ActionVaultPurge — internal/services/authorization/data_actions.go) already
// authorizes the request before this handler runs. No handler-level
// authorization call is needed here, matching every other vault data-plane
// route (secrets/keys/certificates).
func purgeVault(c *Context, w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["vault_name"]

	svc := c.vaultSvc()
	if svc == nil {
		return
	}

	if err := svc.PurgeVault(r.Context(), name); err != nil {
		switch {
		case errors.Is(err, vaultServices.ErrVaultNotFound):
			c.SetNotFound("vault")
		case errors.Is(err, vaultServices.ErrDefaultVaultProtected), errors.Is(err, vaultServices.ErrVaultPurgeProtected):
			c.SetInvalidParam(err.Error())
		default:
			c.SetInternalError(err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
	c.Logger.Printf("Vault %s purged", name)
}
