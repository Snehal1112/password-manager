package api

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/internal/container"
	"rocketvault/model"
)

// deletedOps binds one domain service's three soft-delete methods.
//
// The services spell these differently (ListDeletedSecrets, RecoverKey,
// PurgeCertificate, ...), so they are bound as method values rather than
// reached through a shared interface the services do not implement.
type deletedOps[T any] struct {
	List    func(context.Context, model.Scope) ([]T, error)
	Recover func(context.Context, uuid.UUID, model.Scope) error
	Purge   func(context.Context, uuid.UUID, model.Scope) error
}

// deletedResource describes one resource type's soft-delete surface.
//
// Item stays a per-type function rather than being unified. The three list
// responses deliberately expose different fields, and those shapes are a wire
// contract that must not drift as a side effect of sharing code.
// Envelope wraps the projected rows in this resource's own list response
// type. It is a function rather than a key name because the envelope's first
// key differs per resource, and three explicit types express that better than
// one map with a dynamic key.
type deletedResource[T any] struct {
	IDParam    string // The wire name used in a 400, e.g. "key_id".
	RecoverMsg string // The recover success message.

	ID       func(*ApiParams) string
	Ops      func(*Context) (deletedOps[T], bool)
	Item     func(T) any
	Envelope func([]any) any
	WriteErr func(*Context, error)
}

// deletedSecretsResponse is the GET /deleted/secrets envelope.
//
// Fields are declared in the alphabetical order the map[string]any this
// replaces encoded them in, so the JSON byte order is unchanged. Neither
// field is omitempty: an empty listing must still carry both keys.
type deletedSecretsResponse struct {
	DeletedSecrets []any `json:"deleted_secrets"`
	Total          int   `json:"total"`
}

// deletedKeysResponse is the GET /deleted/keys envelope.
type deletedKeysResponse struct {
	DeletedKeys []any `json:"deleted_keys"`
	Total       int   `json:"total"`
}

// deletedCertificatesResponse is the GET /deleted/certificates envelope.
type deletedCertificatesResponse struct {
	DeletedCertificates []any `json:"deleted_certificates"`
	Total               int   `json:"total"`
}

// recoveredResponse is the envelope returned by a successful restore.
//
// The shape is identical across all three resources, so one type serves. Note
// the declaration order: "id" before "message", because the map this replaces
// sorted its keys and "id" sorts first.
type recoveredResponse struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

// listHandler lists the resolved vault's soft-deleted items.
//
// The vault is read before the user claim, matching the handlers this
// replaces. That order decides which 400 a request with both malformed gets,
// so it is behavior rather than style. scopeFromRequest orders the two the
// other way and is therefore deliberately not used here.
func (res deletedResource[T]) listHandler() func(*Context, http.ResponseWriter, *http.Request) {
	return func(c *Context, w http.ResponseWriter, r *http.Request) {
		vaultID, err := vaultIDFromRequest(r)
		if err != nil {
			c.SetInvalidParam("vault")
			return
		}

		userID, ok := userIDFromClaims(c)
		if !ok {
			return
		}

		ops, ok := res.Ops(c)
		if !ok {
			return
		}

		// The service already filters to soft-deleted entries only.
		items, err := ops.List(r.Context(), model.NewVaultScope(vaultID, userID))
		if err != nil {
			c.SetInternalError(err)
			return
		}

		// An empty result must encode as [] rather than null, which is what the
		// nil-slice guard in the handlers this replaces was for.
		projected := make([]any, 0, len(items))
		for _, item := range items {
			projected = append(projected, res.Item(item))
		}

		writeJSON(w, res.Envelope(projected))
	}
}

// recoverHandler restores one soft-deleted item by ID.
//
// The service is resolved before the scope, matching the handlers this
// replaces.
func (res deletedResource[T]) recoverHandler() func(*Context, http.ResponseWriter, *http.Request) {
	return func(c *Context, w http.ResponseWriter, r *http.Request) {
		id, ok := resourceID(c, res.ID(c.Params), res.IDParam)
		if !ok {
			return
		}

		ops, ok := res.Ops(c)
		if !ok {
			return
		}

		scope, ok := scopeFromRequest(c, r)
		if !ok {
			return
		}

		if err := ops.Recover(r.Context(), id, scope); err != nil {
			res.WriteErr(c, err)
			return
		}

		writeJSON(w, recoveredResponse{ID: id.String(), Message: res.RecoverMsg})
	}
}

// purgeHandler permanently deletes one soft-deleted item by ID.
//
// It resolves the service before the scope for the same reason recoverHandler
// does.
func (res deletedResource[T]) purgeHandler() func(*Context, http.ResponseWriter, *http.Request) {
	return func(c *Context, w http.ResponseWriter, r *http.Request) {
		id, ok := resourceID(c, res.ID(c.Params), res.IDParam)
		if !ok {
			return
		}

		ops, ok := res.Ops(c)
		if !ok {
			return
		}

		scope, ok := scopeFromRequest(c, r)
		if !ok {
			return
		}

		if err := ops.Purge(r.Context(), id, scope); err != nil {
			res.WriteErr(c, err)
			return
		}

		ReturnStatusOK(w)
	}
}

// deletedSecretItem is one row of the deleted-secrets listing.
//
// Unlike its key and certificate siblings below, this replaces a map, so its
// fields are declared in alphabetical json-tag order to keep the encoded byte
// order unchanged. DeletedAt carries no omitempty because the map always
// emitted the key, including as null.
type deletedSecretItem struct {
	CreatedAt any    `json:"created_at"`
	DeletedAt any    `json:"deleted_at"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   int    `json:"version"`
}

// deletedKeyItem is one row of the deleted-keys listing.
type deletedKeyItem struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	DeletedAt       any    `json:"deleted_at"`
	PurgeProtection bool   `json:"purge_protection"`
}

// deletedCertItem is one row of the deleted-certificates listing.
type deletedCertItem struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	DeletedAt       any    `json:"deleted_at"`
	PurgeProtection bool   `json:"purge_protection"`
}

// deletedSecrets describes the secrets soft-delete surface.
var deletedSecrets = deletedResource[model.Secret]{
	IDParam:    "secret_id",
	RecoverMsg: "Secret recovered successfully",
	ID:         func(p *ApiParams) string { return p.SecretID },
	Ops: func(c *Context) (deletedOps[model.Secret], bool) {
		s, ok := svc(c, container.ServiceContainerInterface.GetSecretService)
		if !ok {
			return deletedOps[model.Secret]{}, false
		}
		return deletedOps[model.Secret]{
			List:    s.ListDeletedSecrets,
			Recover: s.RecoverSecret,
			Purge:   s.PurgeSecret,
		}, true
	},
	Item: func(s model.Secret) any {
		return deletedSecretItem{
			CreatedAt: s.CreatedAt,
			DeletedAt: s.DeletedAt,
			ID:        s.ID.String(),
			Name:      s.Name,
			Version:   s.Version,
		}
	},
	Envelope: func(items []any) any {
		return deletedSecretsResponse{DeletedSecrets: items, Total: len(items)}
	},
	WriteErr: writeSecretError,
}

// deletedKeys describes the keys soft-delete surface.
var deletedKeys = deletedResource[model.Key]{
	IDParam:    "key_id",
	RecoverMsg: "Key recovered successfully",
	ID:         func(p *ApiParams) string { return p.KeyID },
	Ops: func(c *Context) (deletedOps[model.Key], bool) {
		s, ok := svc(c, container.ServiceContainerInterface.GetKeyService)
		if !ok {
			return deletedOps[model.Key]{}, false
		}
		return deletedOps[model.Key]{
			List:    s.ListDeletedKeys,
			Recover: s.RecoverKey,
			Purge:   s.PurgeKey,
		}, true
	},
	Item: func(k model.Key) any {
		return deletedKeyItem{
			ID:              k.ID.String(),
			Name:            k.Name,
			Type:            k.Type,
			DeletedAt:       k.DeletedAt,
			PurgeProtection: k.PurgeProtection,
		}
	},
	Envelope: func(items []any) any {
		return deletedKeysResponse{DeletedKeys: items, Total: len(items)}
	},
	WriteErr: writeKeyError,
}

// deletedCertificates describes the certificates soft-delete surface.
var deletedCertificates = deletedResource[model.Certificate]{
	IDParam:    "certificate_id",
	RecoverMsg: "Certificate recovered successfully",
	ID:         func(p *ApiParams) string { return p.CertificateID },
	Ops: func(c *Context) (deletedOps[model.Certificate], bool) {
		s, ok := svc(c, container.ServiceContainerInterface.GetCertificateService)
		if !ok {
			return deletedOps[model.Certificate]{}, false
		}
		return deletedOps[model.Certificate]{
			List:    s.ListDeletedCertificates,
			Recover: s.RecoverCertificate,
			Purge:   s.PurgeCertificate,
		}, true
	},
	Item: func(cert model.Certificate) any {
		return deletedCertItem{
			ID:              cert.ID.String(),
			Name:            cert.Name,
			DeletedAt:       cert.DeletedAt,
			PurgeProtection: cert.PurgeProtection,
		}
	},
	Envelope: func(items []any) any {
		return deletedCertificatesResponse{DeletedCertificates: items, Total: len(items)}
	},
	WriteErr: writeCertificateError,
}

// The nine soft-delete handlers, one per resource and operation.
//
// They are vars of the same names and signatures the functions had, so route
// registration below is unchanged. Per the visibility model, any caller
// authorized for a vault sees all of its soft-deleted items.
var (
	listDeletedSecrets = deletedSecrets.listHandler()
	recoverSecret      = deletedSecrets.recoverHandler()
	purgeSecret        = deletedSecrets.purgeHandler()

	listDeletedKeys = deletedKeys.listHandler()
	recoverKey      = deletedKeys.recoverHandler()
	purgeKey        = deletedKeys.purgeHandler()

	listDeletedCertificates = deletedCertificates.listHandler()
	recoverCertificate      = deletedCertificates.recoverHandler()
	purgeCertificate        = deletedCertificates.purgeHandler()
)

// getDeletedKey returns a single soft-deleted key by its UUID, resolved
// within the same vault scope as listDeletedKeys. It has no vault-scoped
// route counterpart (secrets doesn't have a single-item deleted GET either),
// so it stays registered on the flat router only, where it resolves to the
// default vault.
func getDeletedKey(c *Context, w http.ResponseWriter, r *http.Request) {
	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return
	}
	userID, ok := userIDFromClaims(c)
	if !ok {
		return
	}

	keyID, keyOK := resourceID(c, c.Params.KeyID, "key_id")
	if !keyOK {
		return
	}

	keySvc, svcOK := svc(c, container.ServiceContainerInterface.GetKeyService)
	if !svcOK {
		return
	}

	keys, err := keySvc.ListDeletedKeys(r.Context(), model.NewVaultScope(vaultID, userID))
	if err != nil {
		c.SetInternalError(err)
		return
	}

	for _, k := range keys {
		if k.ID == keyID {
			writeJSON(w, map[string]any{
				"id":               k.ID.String(),
				"name":             k.Name,
				"type":             k.Type,
				"deleted_at":       k.DeletedAt,
				"purge_protection": k.PurgeProtection,
			})
			return
		}
	}
	c.SetNotFound("key")
}

// userIDFromClaims extracts and parses the user UUID from JWT claims.
// Sets c.Err and returns false if the claim is missing or cannot be parsed.
func userIDFromClaims(c *Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Claims.UserID)
	if err != nil {
		c.SetInvalidParam("user_id")
		return uuid.Nil, false
	}
	return id, true
}

// InitDeleted registers soft-delete management routes.
//
// All seven deleted-flow handlers (secrets, keys, certificates) are now
// vault-aware: they read the vault from the request context via
// scopeFromRequest/vaultIDFromRequest, so they are registered on both the
// legacy flat routes and the vault-scoped subrouter. getDeletedKey is the one
// exception — it has no vault-scoped route because it has no secrets
// equivalent to mirror (secrets exposes no single-item deleted GET either);
// it stays flat-only and resolves to the default vault.
func (api *API) InitDeleted() {
	api.registerDeletedRoutes(api.BaseRoutes.Deleted)
	if api.BaseRoutes.VaultScoped != nil {
		api.registerVaultScopedDeletedRoutes(api.BaseRoutes.VaultScoped.PathPrefix("/deleted").Subrouter())
	}
}

// registerDeletedRoutes registers all soft-delete handlers on the legacy flat
// routes. These resolve to the default vault / owner scope.
func (api *API) registerDeletedRoutes(r *mux.Router) {
	api.registerVaultScopedDeletedRoutes(r)

	// getDeletedKey has no vault-scoped counterpart; see the InitDeleted comment.
	r.Handle("/keys/{key_id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getDeletedKey)).Methods("GET")
}

// registerVaultScopedDeletedRoutes registers the vault-aware soft-delete
// handlers for all three resource types. List handlers honour the resolved
// vault; restore/purge operate by globally-unique ID so they already act on
// the correct object once scoped.
func (api *API) registerVaultScopedDeletedRoutes(r *mux.Router) {
	r.Handle("/secrets", ApiSessionRequired(api.App, listDeletedSecrets)).Methods("GET")
	r.Handle("/secrets/{secret_id:[A-Fa-f0-9-]+}/restore", ApiSessionRequired(api.App, recoverSecret)).Methods("POST")
	r.Handle("/secrets/{secret_id:[A-Fa-f0-9-]+}/purge", ApiSessionRequired(api.App, purgeSecret)).Methods("DELETE")
	r.Handle("/keys", ApiSessionRequired(api.App, listDeletedKeys)).Methods("GET")
	r.Handle("/keys/{key_id:[A-Fa-f0-9-]+}/restore", ApiSessionRequired(api.App, recoverKey)).Methods("POST")
	r.Handle("/keys/{key_id:[A-Fa-f0-9-]+}/purge", ApiSessionRequired(api.App, purgeKey)).Methods("DELETE")
	r.Handle("/certificates", ApiSessionRequired(api.App, listDeletedCertificates)).Methods("GET")
	r.Handle("/certificates/{certificate_id:[A-Fa-f0-9-]+}/restore", ApiSessionRequired(api.App, recoverCertificate)).Methods("POST")
	r.Handle("/certificates/{certificate_id:[A-Fa-f0-9-]+}/purge", ApiSessionRequired(api.App, purgeCertificate)).Methods("DELETE")
}
