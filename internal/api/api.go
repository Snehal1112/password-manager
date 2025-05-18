// Package api provides the RESTful API for the password manager.
// It implements endpoints for authentication, secrets management, and health checks.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"password-manager/internal/auth"
	"password-manager/internal/db"
	"password-manager/internal/logging"
	"password-manager/internal/middleware"
	"password-manager/internal/secrets"
)

// TODO: Consider using a more sophisticated logging
// library or framework for production use.
var log *logging.Logger

// Server represents the API server with a router.
type Server struct {
	router *mux.Router
}

// NewServer creates a new API server with configured routes and middleware.
func NewServer(l *logging.Logger) (*Server, error) {
	r := mux.NewRouter()

	log = l

	middleware := middleware.NewMiddleware(l)

	// Public routes (no auth middleware).
	r.HandleFunc("/health", healthHandler).Methods("GET")
	r.HandleFunc("/login", loginHandler).Methods("POST")

	// Protected routes with middleware.
	protected := r.PathPrefix("/").Subrouter()
	protected.Use(
		middleware.LoggingMiddleware,
		middleware.RateLimitMiddleware,
		middleware.AuthMiddleware,
	)
	protected.HandleFunc("/secrets", createSecretHandler).Methods("POST")
	protected.HandleFunc("/secrets/{id}", getSecretHandler).Methods("GET")
	protected.HandleFunc("/secrets", listSecretsHandler).Methods("GET")
	protected.HandleFunc("/secrets/{id}", updateSecretHandler).Methods("PUT")
	protected.HandleFunc("/secrets/{id}", deleteSecretHandler).Methods("DELETE")

	return &Server{router: r}, nil
}

// Start runs the API server on the configured port.
func (s *Server) Start() error {
	port := viper.GetInt("api.port")
	if port == 0 {
		port = 8080
	}
	addr := fmt.Sprintf(":%d", port)
	logrus.Info("Starting API server on ", addr)
	return http.ListenAndServe(addr, s.router)
}

// Stop gracefully shuts down the API server.
func (s *Server) Stop(ctx context.Context) error {
	// No server shutdown mechanism implemented yet; return nil for compatibility.
	return nil
}

// healthHandler returns the server health status.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{"status": "ok"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// loginHandler authenticates a user and returns a JWT.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.LogAuditError("", "login", "failed", "Invalid request body", err)
		http.Error(w, "Bad Request: invalid JSON", http.StatusBadRequest)
		return
	}

	token, err := auth.Login(r.Context(), req.Username, req.Password, req.TOTPCode)
	if err != nil {
		log.LogAuditError("", "login", "failed", "Authentication failed", err)
		http.Error(w, "Unauthorized: invalid credentials", http.StatusUnauthorized)
		return
	}

	response := map[string]string{"token": token}
	w.Header().Set("Content-Type", "application/json")
	log.LogAuditInfo("", "login", "success", "User logged in successfully")
	json.NewEncoder(w).Encode(response)
}

// createSecretHandler creates a new secret.
func createSecretHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("user_id").(uuid.UUID)
	var req struct {
		Name  string   `json:"name"`
		Value string   `json:"value"`
		Tags  []string `json:"tags"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.LogAuditError(userID.String(), "create_secret", "failed", "Invalid request body", err)
		http.Error(w, "Bad Request: invalid JSON", http.StatusBadRequest)
		return
	}

	repo := secrets.NewSecretRepository(db.DB, log)
	secret := secrets.Secret{
		UserID:    userID,
		Name:      req.Name,
		Value:     req.Value,
		Version:   1,
		Tags:      req.Tags,
		CreatedAt: time.Now(),
	}

	if err := repo.Create(r.Context(), secret); err != nil {
		log.LogAuditError(userID.String(), "create_secret", "failed", "Failed to create secret", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	log.LogAuditInfo(userID.String(), "create_secret", "success", "Secret created successfully")
	json.NewEncoder(w).Encode(secret)
}

// getSecretHandler retrieves a secret by ID.
func getSecretHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("user_id").(uuid.UUID)
	vars := mux.Vars(r)
	// id, err := parseID(vars["id"])
	// if err != nil {
	// 	log.LogAuditError(userID.String(), "get_secret", "failed", "Invalid secret ID", err)
	// 	http.Error(w, "Bad Request: invalid ID", http.StatusBadRequest)
	// 	return
	// }

	id := uuid.MustParse(vars["id"])
	repo := secrets.NewSecretRepository(db.DB, log)
	secret, err := repo.Read(r.Context(), id)
	if err != nil {
		log.LogAuditError(userID.String(), "get_secret", "failed", "Failed to retrieve secret", err)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if secret.UserID != userID {
		log.LogAuditError(userID.String(), "get_secret", "failed", "Unauthorized access attempt to secret", nil)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	log.LogAuditInfo(userID.String(), "get_secret", "success", "Secret retrieved successfully")
	json.NewEncoder(w).Encode(secret)
}

// listSecretsHandler lists secrets for the authenticated user.
func listSecretsHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("user_id").(uuid.UUID)
	tags := r.URL.Query()["tags"]

	repo := secrets.NewSecretRepository(db.DB, log)
	secretsList, err := repo.ListByUser(r.Context(), userID, tags)
	if err != nil {
		log.LogAuditError(userID.String(), "list_secrets", "failed", "Failed to list secrets", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	log.LogAuditInfo(userID.String(), "list_secrets", "success", fmt.Sprintf("Secrets listed successfully: %d secrets", len(secretsList)))
	json.NewEncoder(w).Encode(secretsList)
}

// updateSecretHandler updates a secret by ID.
func updateSecretHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("user_id").(uuid.UUID)
	vars := mux.Vars(r)
	id := uuid.MustParse(vars["id"])

	var req struct {
		Value string   `json:"value"`
		Tags  []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.LogAuditError(userID.String(), "update_secret", "failed", "Invalid request body", err)
		http.Error(w, "Bad Request: invalid JSON", http.StatusBadRequest)
		return
	}

	repo := secrets.NewSecretRepository(db.DB, log)
	secret, err := repo.Read(r.Context(), id)
	if err != nil {
		log.LogAuditError(userID.String(), "update_secret", "failed", "Failed to read secret", err)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if secret.UserID != userID {
		log.LogAuditError(userID.String(), "update_secret", "failed", "Unauthorized access attempt to secret", nil)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	secret.Value = req.Value
	secret.Tags = req.Tags
	secret.Version++
	secret.CreatedAt = time.Now()
	if err := repo.Update(r.Context(), secret); err != nil {
		log.LogAuditError(userID.String(), "update_secret", "failed", "Failed to update secret", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	log.LogAuditInfo(userID.String(), "update_secret", "success", "Secret updated successfully")
	json.NewEncoder(w).Encode(secret)
}

// deleteSecretHandler deletes a secret by ID.
func deleteSecretHandler(w http.ResponseWriter, r *http.Request) {
	userID, _ := r.Context().Value("user_id").(uuid.UUID)
	vars := mux.Vars(r)
	id := uuid.MustParse(vars["id"])

	repo := secrets.NewSecretRepository(db.DB, log)
	secret, err := repo.Read(r.Context(), id)
	if err != nil {
		log.LogAuditError(userID.String(), "delete_secret", "failed", "Failed to read secret", err)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if secret.UserID != userID {
		log.LogAuditError(userID.String(), "delete_secret", "failed", "Unauthorized access attempt to secret", nil)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if err := repo.Delete(r.Context(), id); err != nil {
		log.LogAuditError(userID.String(), "delete_secret", "failed", "Failed to delete secret", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	log.LogAuditInfo(userID.String(), "delete_secret", "success", "Secret deleted successfully")
}

// parseID parses a string ID to a UUID.
func parseID(id string) (uuid.UUID, error) {
	return uuid.Parse(id)
}
