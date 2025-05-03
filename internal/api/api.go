package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/snehal1112/password-manager/internal/auth"
	"github.com/snehal1112/password-manager/internal/secret"
	"github.com/snehal1112/password-manager/internal/store"
	"github.com/spf13/viper"
)

// APIServer manages the RESTful API server.
// It handles routing, middleware, and store interactions.
type APIServer struct {
	router      *mux.Router
	secretStore store.Store[*secret.Secret]
	userStore   store.Store[*auth.User]
	jwtSecret   string
}

// NewAPIServer creates a new API server.
// It initializes routes and middleware for secret and user endpoints.
//
// Parameters:
//
//	secretStore: The store for secret entities.
//	userStore: The store for user entities.
//	jwtSecret: The secret key for JWT validation.
//
// Returns:
//
//	A pointer to the initialized APIServer.
//
// The function is used to set up the REST API server.
func NewAPIServer(secretStore store.Store[*secret.Secret], userStore store.Store[*auth.User], jwtSecret string) *APIServer {
	s := &APIServer{
		router:      mux.NewRouter(),
		secretStore: secretStore,
		userStore:   userStore,
		jwtSecret:   jwtSecret,
	}
	s.setupRoutes()
	return s
}

// setupRoutes configures the API routes and middleware.
// It defines endpoints for secrets and users with JWT authentication.
func (s *APIServer) setupRoutes() {
	// Public endpoint
	s.router.HandleFunc("/users", s.handleCreateUser).Methods("POST")

	// Protected endpoints
	protected := s.router.PathPrefix("/").Subrouter()
	protected.Use(s.jwtMiddleware)
	protected.HandleFunc("/users/{id}", s.handleGetUser).Methods("GET")
	protected.HandleFunc("/secrets", s.handleCreateSecret).Methods("POST")
	protected.HandleFunc("/secrets/{id}", s.handleGetSecret).Methods("GET")
	protected.HandleFunc("/secrets/{id}", s.handleUpdateSecret).Methods("PUT")
	protected.HandleFunc("/secrets/{id}", s.handleDeleteSecret).Methods("DELETE")
}

// jwtMiddleware validates JWT tokens.
// It checks the Authorization header and adds user_id to the context.
//
// Parameters:
//
//	next: The next handler in the middleware chain.
//
// Returns:
//
//	An http.Handler that processes the request if the token is valid.
//
// The middleware is used to secure protected endpoints.
func (s *APIServer) jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			logrus.Warn("Missing Authorization header")
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			logrus.Warn("Invalid Authorization header format")
			http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(s.jwtSecret), nil
		})
		if err != nil {
			logrus.WithError(err).Warn("Failed to parse JWT")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			logrus.Warn("Invalid token claims")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		userID, ok := claims["user_id"].(string)
		if !ok {
			logrus.Warn("Missing user_id in token")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// handleCreateUser handles POST /users.
// It creates a new user with the provided credentials.
//
// Parameters:
//
//	w: The HTTP response writer.
//	r: The HTTP request containing user data (username, password, id).
//
// Returns:
//
//	None. Writes JSON response to w.
//
// The handler is used to register new users.
func (s *APIServer) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		ID       string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.WithError(err).Warn("Failed to decode request")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := auth.NewUser(req.Username, req.Password, req.ID)
	if err != nil {
		logrus.WithError(err).Error("Failed to create user")
		http.Error(w, "Failed to create user", http.StatusBadRequest)
		return
	}

	if err := s.userStore.Save(user); err != nil {
		logrus.WithError(err).Error("Failed to save user")
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": user.ID})
	logrus.WithFields(logrus.Fields{"user_id": user.ID}).Info("User created")
}

// handleGetUser handles GET /users/{id}.
// It retrieves a user by ID.
//
// Parameters:
//
//	w: The HTTP response writer.
//	r: The HTTP request with user ID in the path.
//
// Returns:
//
//	None. Writes JSON response to w.
//
// The handler is used to fetch user details.
func (s *APIServer) handleGetUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	user, err := s.userStore.Get(id)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"user_id": id}).Warn("Failed to get user")
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":       user.ID,
		"username": user.Username,
	})
	logrus.WithFields(logrus.Fields{"user_id": id}).Info("User retrieved")
}

// handleCreateSecret handles POST /secrets.
// It creates a new secret with the provided value.
//
// Parameters:
//
//	w: The HTTP response writer.
//	r: The HTTP request containing secret data (id, value).
//
// Returns:
//
//	None. Writes JSON response to w.
//
// The handler is used to store new secrets.
func (s *APIServer) handleCreateSecret(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID    string `json:"id"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.WithError(err).Warn("Failed to decode request")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	sec, err := secret.NewSecret(req.ID, req.Value, viper.GetString("master_key"))
	if err != nil {
		logrus.WithError(err).Error("Failed to create secret")
		http.Error(w, "Failed to create secret", http.StatusBadRequest)
		return
	}

	if err := s.secretStore.Save(sec); err != nil {
		logrus.WithError(err).Error("Failed to save secret")
		http.Error(w, "Failed to save secret", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": sec.ID})
	logrus.WithFields(logrus.Fields{"secret_id": sec.ID}).Info("Secret created")
}

// handleGetSecret handles GET /secrets/{id}.
// It retrieves and decrypts a secret by ID.
//
// Parameters:
//
//	w: The HTTP response writer.
//	r: The HTTP request with secret ID in the path.
//
// Returns:
//
//	None. Writes JSON response to w.
//
// The handler is used to fetch and decrypt secret values.
func (s *APIServer) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	sec, err := s.secretStore.Get(id)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"secret_id": id}).Warn("Failed to get secret")
		http.Error(w, "Secret not found", http.StatusNotFound)
		return
	}

	value, err := sec.DecryptAES(viper.GetString("master_key"))
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"secret_id": id}).Error("Failed to decrypt secret")
		http.Error(w, "Failed to decrypt secret", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         sec.ID,
		"value":      value,
		"version":    sec.Version,
		"created_at": sec.CreatedAt,
		"rotate_at":  sec.RotateAt,
	})
	logrus.WithFields(logrus.Fields{"secret_id": id}).Info("Secret retrieved and decrypted")
}

// handleUpdateSecret handles PUT /secrets/{id}.
// It updates a secret with a new value.
//
// Parameters:
//
//	w: The HTTP response writer.
//	r: The HTTP request with secret ID in the path and new value in the body.
//
// Returns:
//
//	None. Writes JSON response to w.
//
// The handler is used to update existing secrets.
func (s *APIServer) handleUpdateSecret(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.WithError(err).Warn("Failed to decode request")
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	sec, err := s.secretStore.Get(id)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"secret_id": id}).Warn("Failed to get secret")
		http.Error(w, "Secret not found", http.StatusNotFound)
		return
	}

	sec.Version++
	sec.Value, err = secret.EncryptAES(req.Value, viper.GetString("master_key"))
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"secret_id": id}).Error("Failed to encrypt secret")
		http.Error(w, "Failed to encrypt secret", http.StatusInternalServerError)
		return
	}

	if err := s.secretStore.Update(sec); err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"secret_id": id}).Error("Failed to update secret")
		http.Error(w, "Failed to update secret", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"id": sec.ID})
	logrus.WithFields(logrus.Fields{"secret_id": id}).Info("Secret updated")
}

// handleDeleteSecret handles DELETE /secrets/{id}.
// It deletes a secret by ID.
//
// Parameters:
//
//	w: The HTTP response writer.
//	r: The HTTP request with secret ID in the path.
//
// Returns:
//
//	None. Writes JSON response to w.
//
// The handler is used to remove secrets from storage.
func (s *APIServer) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	if err := s.secretStore.Delete(id); err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{"secret_id": id}).Warn("Failed to delete secret")
		http.Error(w, "Secret not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Secret deleted"})
	logrus.WithFields(logrus.Fields{"secret_id": id}).Info("Secret deleted")
}

// Start runs the API server.
// It listens on the specified host and port.
//
// Parameters:
//
//	host: The host address (e.g., "localhost").
//	port: The port number (e.g., "8080").
//
// Returns:
//
//	An error if the server fails to start.
//
// The function is used to launch the HTTP server.
func (s *APIServer) Start(host, port string) error {
	addr := fmt.Sprintf("%s:%s", host, port)
	logrus.WithFields(logrus.Fields{"address": addr}).Info("Starting API server")
	return http.ListenAndServe(addr, s.router)
}
