package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/app"
	"rocketvault/common"
	"rocketvault/internal/logging"
	"rocketvault/internal/repositories"
	authServices "rocketvault/internal/services/auth"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	secretServices "rocketvault/internal/services/secrets"
	userServices "rocketvault/internal/services/users"
	"rocketvault/model"
)

// Context holds request-scoped data for every API handler.
type Context struct {
	App            *app.App
	T              common.TranslateFunc
	Err            *common.AppError
	RequestID      string
	IPAddress      string
	Token          string
	Claims         jwt.MapClaims
	Path           string
	UserAgent      string
	AcceptLanguage string
	Params         *ApiParams
	Logger         *logging.Logger
}

// vaultIDFromRequest returns the vault id resolved by VaultResolutionMiddleware
// and stored in the request context. When the value is absent or empty (for
// example in unit tests that bypass the middleware), it falls back to the
// well-known default vault id so legacy flat routes keep working.
func vaultIDFromRequest(r *http.Request) (uuid.UUID, error) {
	s, _ := r.Context().Value(common.VaultIDKey).(string)
	if s == "" {
		s = model.DefaultVaultID
	}
	return uuid.Parse(s)
}

// scopeFromRequest builds the authorization scope for a resource operation. It
// is the only scope constructor on the data plane: ownership is provenance and
// audit metadata, never an access predicate. Crypto operations are gated by the
// Key Vault Crypto User role at vault scope, not by who created the key.
//
// Vault-scoped routes (/api/v1/vaults/{vault_name}/...) yield a vault scope, so
// any vault member may act. Legacy flat routes yield an owner scope, preserving
// pre-multi-vault per-user visibility. A future task collapses both onto the
// vault scope.
//
// It sets c.Err and returns false when the caller's identity cannot be
// determined, so a handler can never proceed with an invalid scope.
func scopeFromRequest(c *Context, r *http.Request) (model.Scope, bool) {
	userID, ok := userIDFromClaims(c)
	if !ok {
		return model.Scope{}, false
	}

	vaultID, err := vaultIDFromRequest(r)
	if err != nil {
		c.SetInvalidParam("vault")
		return model.Scope{}, false
	}

	if mux.Vars(r)["vault_name"] != "" {
		return model.NewVaultScope(vaultID, userID), true
	}
	return model.NewOwnerScope(vaultID, userID), true
}

// SetInvalidParam sets a 400 error for a missing or malformed parameter.
func (c *Context) SetInvalidParam(parameter string) {
	c.Err = common.NewAppError("api.context.set_invalid_param",
		"Invalid or missing parameter: "+parameter, nil, "", http.StatusBadRequest)
}

// SetPermissionError sets a 403 error for insufficient permissions.
func (c *Context) SetPermissionError(permission string) {
	c.Err = common.NewAppError("api.context.set_permission_error",
		"Insufficient permissions: "+permission, nil, "", http.StatusForbidden)
}

// SetNotFound sets a 404 error for a missing resource.
func (c *Context) SetNotFound(resource string) {
	c.Err = common.NewAppError("api.context.set_not_found",
		resource+" not found", nil, "", http.StatusNotFound)
}

// SetInternalError sets a 500 error for unexpected failures.
func (c *Context) SetInternalError(err error) {
	msg := "Internal server error"
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	c.Err = common.NewAppError("api.context.set_internal_error", msg, nil, detail, http.StatusInternalServerError)
}

// ApiHandler wraps public (unauthenticated) handlers.
func ApiHandler(app *app.App, handler func(*Context, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := &Context{
			App:            app,
			Params:         ApiParamsFromRequest(r),
			RequestID:      "req-" + uuid.New().String()[:8],
			IPAddress:      r.RemoteAddr,
			Path:           r.URL.Path,
			UserAgent:      r.UserAgent(),
			AcceptLanguage: r.Header.Get("Accept-Language"),
			Logger:         app.Logger,
		}

		if ctx.Logger != nil {
			ctx.Logger.Printf("Handling %s %s", r.Method, r.URL.Path)
		}

		handler(ctx, w, r)

		if ctx.Logger != nil {
			ctx.Logger.Printf("Completed %s %s in %dms", r.Method, r.URL.Path, time.Since(start).Milliseconds())
		}

		if ctx.Err != nil {
			writeError(w, ctx)
		}
	}
}

// SessionRequired is an alias for ApiSessionRequired for backward compatibility.
var SessionRequired = ApiSessionRequired

// ApiSessionRequired wraps handlers that require an authenticated session.
func ApiSessionRequired(a *app.App, handler func(*Context, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		userIDStr, ok := r.Context().Value(common.UserIDKey).(string)
		if !ok || userIDStr == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck,gosec
				"id":          "api.context.session_required",
				"message":     "Unauthorized: missing session",
				"status_code": http.StatusUnauthorized,
			})
			return
		}

		username, _ := r.Context().Value(common.UsernameKey).(string)
		role, _ := r.Context().Value(common.RoleKey).(string)

		if a.ServiceContainer != nil {
			if err := a.ServiceContainer.GetRBACService().ValidateEndpointAccess(role, r.Method, r.URL.Path); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck,gosec
					"id":          "api.context.permissions",
					"message":     "Access denied",
					"status_code": http.StatusForbidden,
				})
				return
			}
		}

		ctx := &Context{
			App: a,
			Claims: jwt.MapClaims{
				"user_id":  userIDStr,
				"username": username,
				"role":     role,
			},
			Params:         ApiParamsFromRequest(r),
			RequestID:      "req-" + uuid.New().String()[:8],
			IPAddress:      r.RemoteAddr,
			Path:           r.URL.Path,
			UserAgent:      r.UserAgent(),
			AcceptLanguage: r.Header.Get("Accept-Language"),
			Logger:         a.Logger,
		}

		if ctx.Logger != nil {
			ctx.Logger.Printf("Handling %s %s (user: %s)", r.Method, r.URL.Path, userIDStr)
		}

		handler(ctx, w, r)

		if ctx.Logger != nil {
			ctx.Logger.Printf("Completed %s %s in %dms", r.Method, r.URL.Path, time.Since(start).Milliseconds())
		}

		if ctx.Err != nil {
			writeError(w, ctx)
		}
	}
}

// writeError writes a structured JSON error response with request_id.
func writeError(w http.ResponseWriter, c *Context) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c.Err.StatusCode)
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck,gosec
		"id":             c.Err.ID,
		"message":        c.Err.Message,
		"detailed_error": c.Err.DetailedError,
		"status_code":    c.Err.StatusCode,
		"request_id":     c.RequestID,
	})
}

func (c *Context) secretSvc() secretServices.SecretService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetSecretService()
}

func (c *Context) keySvc() keyServices.KeyService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetKeyService()
}

func (c *Context) cryptoSvc() keyServices.CryptoService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetCryptoService()
}

func (c *Context) userSvc() userServices.UserService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetUserService()
}

func (c *Context) certSvc() certServices.CertificateService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetCertificateService()
}

func (c *Context) authSvc() authServices.AuthenticationService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetAuthenticationService()
}

func (c *Context) keyRotationPolicyRepo() repositories.KeyRotationPolicyRepositoryInterface {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.SetInternalError(nil)
		return nil
	}
	return c.App.ServiceContainer.GetKeyRotationPolicyRepository()
}
