/*
Copyright © 2025 Snehal Dangroshiya

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

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
	authServices "rocketvault/internal/services/auth"
	certServices "rocketvault/internal/services/certificates"
	keyServices "rocketvault/internal/services/keys"
	secretServices "rocketvault/internal/services/secrets"
	userServices "rocketvault/internal/services/users"
	"rocketvault/internal/repositories"
)

// Context holds the contextual information for a request in the vault-service application.
// It includes references to the application instance, translation function, error details,
// request ID, IP address, and request path.
type Context struct {
	App            *app.App
	T              common.TranslateFunc
	Err            *common.AppError
	RequestID      string          // Unique request identifier
	IPAddress      string          // Client IP address
	Token          string          // JWT token
	Claims         jwt.MapClaims   // JWT claims
	Path           string          // Request URL path
	UserAgent      string          // Client User-Agent
	AcceptLanguage string          // Client Accept-Language
	Params         *Params         // URL and query parameters
	Logger         *logging.Logger // Logger for the request context
}

// Params holds URL and query parameters for various endpoints.
type Params struct {
	UserID string            // For /users/{user_id}
	Query  map[string]string // Query parameters (e.g., ?page=1)
}

// Handler wraps handlers with common logic, similar to Mattermost's APIHandler.
func Handler(app *app.App, handler func(*Context, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := &Context{
			App:            app,
			Token:          "",
			Claims:         nil,
			Params:         &Params{Query: make(map[string]string)},
			RequestID:      "req-" + uuid.New().String()[:8],
			IPAddress:      r.RemoteAddr,
			Path:           r.URL.Path,
			UserAgent:      r.UserAgent(),
			AcceptLanguage: r.Header.Get("Accept-Language"),
			Logger:         app.Logger,
			Err:            nil,
		}

		ctx.Logger.WithField("request_id", ctx.RequestID).Debug("API request started")
		// Populate URL parameters
		vars := mux.Vars(r)
		if userID, ok := vars["user_id"]; ok {
			ctx.Params.UserID = userID
		}

		// Populate query parameters
		query := r.URL.Query()
		for key, values := range query {
			if len(values) > 0 {
				ctx.Params.Query[key] = values[0]
			}
		}

		// Log request
		ctx.Logger.Printf("Handling %s %s", r.Method, r.URL.Path)

		// Execute handler
		handler(ctx, w, r)

		// Log metrics
		elapsed := time.Since(start).Milliseconds()
		ctx.Logger.Printf("Completed %s %s in %dms", r.Method, r.URL.Path, elapsed)

		// Handle errors
		if ctx.Err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ctx.Err.StatusCode)
			json.NewEncoder(w).Encode(map[string]any{
				"id":             ctx.Err.ID,
				"message":        ctx.Err.Message,
				"detailed_error": ctx.Err.DetailedError,
				"status_code":    ctx.Err.StatusCode,
			})
		}
	}
}

// SessionRequired wraps handlers requiring an authenticated session.
// Identity is read from r.Context() which AuthenticationMiddleware already
// populated — the token is NOT re-validated here.
func SessionRequired(a *app.App, handler func(*Context, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Read identity set by AuthenticationMiddleware.
		userIDStr, ok := r.Context().Value(common.UserIDKey).(string)
		if !ok || userIDStr == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{
				"id":          "Unauthorized",
				"message":     "Unauthorized: missing session",
				"status_code": http.StatusUnauthorized,
			})
			return
		}

		username, _ := r.Context().Value(common.UsernameKey).(string)
		role, _ := r.Context().Value(common.RoleKey).(string)

		// RBAC check using role already verified by middleware.
		if a.ServiceContainer != nil {
			if err := a.ServiceContainer.GetRBACService().ValidateEndpointAccess(role, r.Method, r.URL.Path); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]any{
					"id":          "Forbidden",
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
			Params:         &Params{Query: make(map[string]string)},
			RequestID:      "req-" + uuid.New().String()[:8],
			IPAddress:      r.RemoteAddr,
			Path:           r.URL.Path,
			UserAgent:      r.UserAgent(),
			AcceptLanguage: r.Header.Get("Accept-Language"),
			Logger:         a.Logger,
			Err:            nil,
		}

		// Populate URL parameters.
		vars := mux.Vars(r)
		if uid, ok := vars["user_id"]; ok {
			ctx.Params.UserID = uid
		}

		// Populate query parameters.
		for key, values := range r.URL.Query() {
			if len(values) > 0 {
				ctx.Params.Query[key] = values[0]
			}
		}

		if ctx.Logger != nil {
			ctx.Logger.WithField("user_id", userIDStr).Debug("Session validated via context.")
			ctx.Logger.Printf("Handling %s %s (user: %s)", r.Method, r.URL.Path, userIDStr)
		}

		handler(ctx, w, r)

		if ctx.Logger != nil {
			elapsed := time.Since(start).Milliseconds()
			ctx.Logger.Printf("Completed %s %s in %dms", r.Method, r.URL.Path, elapsed)
		}

		if ctx.Err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ctx.Err.StatusCode)
			json.NewEncoder(w).Encode(map[string]any{
				"id":             ctx.Err.ID,
				"message":        ctx.Err.Message,
				"detailed_error": ctx.Err.DetailedError,
				"status_code":    ctx.Err.StatusCode,
			})
		}
	}
}

// secretSvc returns the secret service, setting c.Err if unavailable.
func (c *Context) secretSvc() secretServices.SecretService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.Err = common.NewAppError("internal", "Service unavailable", nil, "service container is nil", http.StatusInternalServerError)
		return nil
	}
	return c.App.ServiceContainer.GetSecretService()
}

// keySvc returns the key service, setting c.Err if unavailable.
func (c *Context) keySvc() keyServices.KeyService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.Err = common.NewAppError("internal", "Service unavailable", nil, "service container is nil", http.StatusInternalServerError)
		return nil
	}
	return c.App.ServiceContainer.GetKeyService()
}

// userSvc returns the user service, setting c.Err if unavailable.
func (c *Context) userSvc() userServices.UserService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.Err = common.NewAppError("internal", "Service unavailable", nil, "service container is nil", http.StatusInternalServerError)
		return nil
	}
	return c.App.ServiceContainer.GetUserService()
}

// certSvc returns the certificate service, setting c.Err if unavailable.
func (c *Context) certSvc() certServices.CertificateService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.Err = common.NewAppError("internal", "Service unavailable", nil, "service container is nil", http.StatusInternalServerError)
		return nil
	}
	return c.App.ServiceContainer.GetCertificateService()
}

// authSvc returns the authentication service, setting c.Err if unavailable.
func (c *Context) authSvc() authServices.AuthenticationService {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.Err = common.NewAppError("internal", "Service unavailable", nil, "service container is nil", http.StatusInternalServerError)
		return nil
	}
	return c.App.ServiceContainer.GetAuthenticationService()
}

// sessionRepo returns the session repository, setting c.Err if unavailable.
func (c *Context) sessionRepo() repositories.SessionRepositoryInterface {
	if c.App == nil || c.App.ServiceContainer == nil {
		c.Err = common.NewAppError("internal", "Service unavailable", nil, "service container is nil", http.StatusInternalServerError)
		return nil
	}
	return c.App.ServiceContainer.GetSessionRepository()
}
