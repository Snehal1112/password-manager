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
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"

	"password-manager/app"
	"password-manager/internal/logging"
	"password-manager/model"
)

// Context holds the contextual information for a request in the vault-service application.
// It includes references to the application instance, translation function, error details,
// request ID, IP address, and request path.
type Context struct {
	App            *app.App
	T              model.TranslateFunc
	Err            *model.AppError
	RequestID      string
	IPAddress      string
	Token          string          // JWT token
	Claims         jwt.MapClaims   // JWT claims
	RequestId      string          // Unique request identifier
	IpAddress      string          // Client IP address
	Path           string          // Request URL path
	UserAgent      string          // Client User-Agent
	AcceptLanguage string          // Client Accept-Language
	Params         *Params         // URL and query parameters
	Logger         *logging.Logger // Logger for the request context
}

// Params holds URL and query parameters for various endpoints.
type Params struct {
	UserId string            // For /users/{user_id}
	Query  map[string]string // Query parameters (e.g., ?page=1)
}

// APIHandler wraps handlers with common logic, similar to Mattermost's APIHandler.
func APIHandler(app *app.App, handler func(*Context, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := &Context{
			App:            app,
			Token:          "",
			Claims:         nil,
			Params:         &Params{Query: make(map[string]string)},
			RequestId:      "req-" + uuid.New().String()[:8],
			IpAddress:      r.RemoteAddr,
			Path:           r.URL.Path,
			UserAgent:      r.UserAgent(),
			AcceptLanguage: r.Header.Get("Accept-Language"),
			Logger:         app.Logger,
			Err:            nil,
		}

		app.Logger.Println("API request started", ctx.RequestId)
		ctx.Logger.Errorln(model.T("server.error.in.start"))
		// Populate URL parameters
		vars := mux.Vars(r)
		if userId, ok := vars["user_id"]; ok {
			ctx.Params.UserId = userId
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
			log.Println("Error occurred:", w.Header().Clone())
			w.WriteHeader(ctx.Err.StatusCode)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":             ctx.Err.ID,
				"message":        ctx.Err.Message,
				"detailed_error": ctx.Err.DetailedError,
				"status_code":    ctx.Err.StatusCode,
			})
		}
	}
}

// ApiSessionRequired wraps handlers requiring authentication, similar to Mattermost's ApiSessionRequired.
func ApiSessionRequired(app *app.App, handler func(*Context, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := &Context{
			App:            app,
			Token:          "",
			Claims:         nil,
			Params:         &Params{Query: make(map[string]string)},
			RequestId:      "req-" + uuid.New().String()[:8],
			IpAddress:      r.RemoteAddr,
			Path:           r.URL.Path,
			UserAgent:      r.UserAgent(),
			AcceptLanguage: r.Header.Get("Accept-Language"),
			Logger:         app.Logger,
			Err:            nil,
		}

		// Extract JWT token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			ctx.Err = model.NewAppError("ApiSessionRequired", "Missing Authorization header", nil, "", http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ctx.Err.StatusCode)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      ctx.Err.ID,
				"message": ctx.Err.Message,
			})
			return
		}

		parts := strings.Split(authHeader, "Bearer ")
		if len(parts) != 2 {
			ctx.Err = model.NewAppError("ApiSessionRequired", "Invalid Authorization header format", nil, "", http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ctx.Err.StatusCode)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      ctx.Err.ID,
				"message": ctx.Err.Message,
			})
			return
		}

		tokenString := parts[1]
		token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(viper.GetString("jwt.secret")), nil
		})

		if err != nil || !token.Valid {
			ctx.Err = model.NewAppError("ApiSessionRequired", "Invalid or expired token", nil, err.Error(), http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ctx.Err.StatusCode)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      ctx.Err.ID,
				"message": ctx.Err.Message,
			})
			return
		}

		// Populate claims
		if claims, ok := token.Claims.(*jwt.MapClaims); ok {
			ctx.Claims = *claims
			ctx.Token = tokenString
		} else {
			ctx.Err = model.NewAppError("ApiSessionRequired", "Invalid token claims", nil, "", http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ctx.Err.StatusCode)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      ctx.Err.ID,
				"message": ctx.Err.Message,
			})
			return
		}

		// Validate user
		userID, ok := ctx.Claims["sub"].(string)
		if !ok {
			ctx.Err = model.NewAppError("ApiSessionRequired", "Missing user ID in token", nil, "", http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ctx.Err.StatusCode)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      ctx.Err.ID,
				"message": ctx.Err.Message,
			})
			return
		}

		log.Println("Validating user ID:", userID)
		//user, err := app.ValidateUser(userID)
		if err != nil {
			// ctx.Err = err
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ctx.Err.StatusCode)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      ctx.Err.ID,
				"message": ctx.Err.Message,
			})
			return
		}

		// Populate query parameters
		query := r.URL.Query()
		for key, values := range query {
			if len(values) > 0 {
				ctx.Params.Query[key] = values[0]
			}
		}

		// Log request
		ctx.Logger.Printf("Handling %s %s (user: %s)", r.Method, r.URL.Path, "user.ID")

		// Execute handler
		handler(ctx, w, r)

		// Log metrics
		elapsed := time.Since(start).Milliseconds()
		ctx.Logger.Printf("Completed %s %s in %dms", r.Method, r.URL.Path, elapsed)

		// Handle errors
		if ctx.Err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ctx.Err.StatusCode)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":             ctx.Err.ID,
				"message":        ctx.Err.Message,
				"detailed_error": ctx.Err.DetailedError,
			})
		}
	}
}
