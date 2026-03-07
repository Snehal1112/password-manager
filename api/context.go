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
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"password-manager/app"
	"password-manager/common"
	"password-manager/internal/logging"
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

// SessionRequired wraps handlers requiring authentication, similar to Mattermost's SessionRequired.
func SessionRequired(app *app.App, handler func(*Context, http.ResponseWriter, *http.Request)) http.HandlerFunc {
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

		// Extract JWT token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			ctx.Err = common.NewAppError("SessionRequired", "Missing Authorization header", nil, "", http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ctx.Err.StatusCode)
			json.NewEncoder(w).Encode(map[string]any{
				"id":             ctx.Err.ID,
				"message":        ctx.Err.Message,
				"detailed_error": ctx.Err.DetailedError,
				"status_code":    ctx.Err.StatusCode,
			})
			return
		}

		parts := strings.Split(authHeader, "Bearer ")
		if len(parts) != 2 {
			ctx.Err = common.NewAppError("SessionRequired", "Invalid Authorization header format", nil, "", http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ctx.Err.StatusCode)
			json.NewEncoder(w).Encode(map[string]any{
				"id":             ctx.Err.ID,
				"message":        ctx.Err.Message,
				"detailed_error": ctx.Err.DetailedError,
				"status_code":    ctx.Err.StatusCode,
			})
			return
		}

		tokenString := parts[1]

		// Validate token via the auth service — no inline JWT parsing here.
		if app.ServiceContainer == nil {
			ctx.Err = common.NewAppError("SessionRequired", "Service container not available", nil, "", http.StatusInternalServerError)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ctx.Err.StatusCode)
			json.NewEncoder(w).Encode(map[string]any{
				"id":          ctx.Err.ID,
				"message":     ctx.Err.Message,
				"status_code": ctx.Err.StatusCode,
			})
			return
		}

		jwtClaims, err := app.ServiceContainer.GetAuthenticationService().ValidateSession(r.Context(), tokenString)
		if err != nil {
			ctx.Err = common.NewAppError("SessionRequired", "Invalid or expired token", nil, err.Error(), http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ctx.Err.StatusCode)
			json.NewEncoder(w).Encode(map[string]any{
				"id":             ctx.Err.ID,
				"message":        ctx.Err.Message,
				"detailed_error": ctx.Err.DetailedError,
				"status_code":    ctx.Err.StatusCode,
			})
			return
		}

		// Populate ctx.Claims as jwt.MapClaims for handler compatibility.
		userID := jwtClaims.UserID.String()
		role := jwtClaims.Role
		ctx.Claims = jwt.MapClaims{
			"user_id":  userID,
			"username": jwtClaims.Username,
			"role":     role,
			"sub":      jwtClaims.Subject,
		}
		ctx.Token = tokenString

		// Validate endpoint access using RBAC
		if err := app.ServiceContainer.GetRBACService().ValidateEndpointAccess(role, r.Method, r.URL.Path); err != nil {
			ctx.Err = common.NewAppError("SessionRequired", "Access denied", nil, err.Error(), http.StatusForbidden)
			// ... error handling
			return
		}

		ctx.Logger.WithField("user_id", userID).Debug("Session validated via JWT.")

		// Populate query parameters
		query := r.URL.Query()
		for key, values := range query {
			if len(values) > 0 {
				ctx.Params.Query[key] = values[0]
			}
		}

		// Populate URL parameters
		vars := mux.Vars(r)
		if userID, ok := vars["user_id"]; ok {
			ctx.Params.UserID = userID
		}

		// Log request
		ctx.Logger.Printf("Handling %s %s (user: %s)", r.Method, r.URL.Path, userID)

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
			})
		}
	}
}
