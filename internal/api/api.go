package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/snehal1112/password-manager/internal/auth"
	"github.com/snehal1112/password-manager/internal/db"
	"github.com/snehal1112/password-manager/internal/keys"
	"github.com/snehal1112/password-manager/internal/middleware"
	"github.com/snehal1112/password-manager/internal/secrets"
	"github.com/spf13/viper"
)

// StartServer initializes and starts the API server with predefined routes and middleware.
//
// The server uses the Gorilla Mux router to define the following routes:
// - Public Routes:
//   - POST /login: Handles user login.
//
// - Protected Routes (require authentication):
//   - GET /api/secrets: Lists all secrets.
//   - POST /api/secrets: Creates a new secret.
//   - PUT /api/secrets/{name}: Updates an existing secret by name.
//   - DELETE /api/secrets/{name}/{version}: Deletes a specific version of a secret by name.
//   - GET /api/secrets/export: Exports all secrets.
//   - POST /api/keys: Generates a new key.
//   - POST /api/keys/cert: Generates a new certificate.
//   - GET /api/keys/{name}: Retrieves a key by name.
//   - POST /api/keys/{name}/revoke: Revokes a key by name.
//
// Middleware applied:
// - LoggingMiddleware: Logs incoming requests.
// - RateLimitMiddleware: Enforces rate limiting on requests.
// - AuthMiddleware (for protected routes): Ensures requests are authenticated.
//
// The server listens on the port specified by the "api.port" configuration key.
//
// Returns:
// - An error if the server fails to start.
func StartServer() error {
	r := mux.NewRouter()

	// Apply global middleware
	r.Use(middleware.LoggingMiddleware)
	r.Use(middleware.RateLimitMiddleware)

	// Public routes
	r.HandleFunc("/login", LoginHandler).Methods("POST")

	// Protected routes
	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(middleware.AuthMiddleware)
	protected.HandleFunc("/secrets", ListSecrets).Methods("GET")
	protected.HandleFunc("/secrets", CreateSecret).Methods("POST")
	protected.HandleFunc("/secrets/{name}", UpdateSecret).Methods("PUT")
	protected.HandleFunc("/secrets/{name}/{version}", DeleteSecret).Methods("DELETE")
	protected.HandleFunc("/secrets/export", ExportSecretsHandler).Methods("GET")
	protected.HandleFunc("/keys", GenerateKey).Methods("POST")
	protected.HandleFunc("/keys/cert", GenerateCertificate).Methods("POST")
	protected.HandleFunc("/keys/{name}", GetKey).Methods("GET")
	protected.HandleFunc("/keys/{name}/revoke", RevokeKey).Methods("POST")

	// Start server
	port := viper.GetString("api.port")
	logrus.Infof("Starting API server on port %s", port)
	return http.ListenAndServe(":"+port, r)
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

type SecretRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type KeyRequest struct {
	Name string `json:"name"`
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.Error("Failed to decode login request: ", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	token, err := auth.Login(req.Username, req.Password, req.TOTPCode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
	logrus.Info("Login successful for user: ", req.Username)
}

func ListSecrets(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*auth.Claims)
	if !ok {
		logrus.Error("Failed to retrieve user claims from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := db.DB.Query(
		"SELECT name, value, version, created_at FROM secrets WHERE user_id = ? ORDER BY name, version",
		user.UserID,
	)
	if err != nil {
		logrus.Error("Failed to query secrets: ", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var secretsList []secrets.Secret
	for rows.Next() {
		var s secrets.Secret
		var encryptedValue string
		if err := rows.Scan(&s.Name, &encryptedValue, &s.Version, &s.CreatedAt); err != nil {
			logrus.Error("Failed to scan secret: ", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		s.Value, err = secrets.Decrypt(encryptedValue, viper.GetString("master_key"))
		if err != nil {
			logrus.Error("Failed to decrypt secret: ", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		s.UserID = user.UserID
		secretsList = append(secretsList, s)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(secretsList)
	logrus.WithFields(logrus.Fields{
		"username": user.Username,
		"count":    len(secretsList),
	}).Info("Secrets listed")
}

func CreateSecret(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*auth.Claims)
	if !ok {
		logrus.Error("Failed to retrieve user claims from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req SecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.Error("Failed to decode secret request: ", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	s := secrets.Secret{
		Name:   req.Name,
		Value:  req.Value,
		UserID: user.UserID,
	}

	if err := s.CreateSecret(user.UserID, req.Name, req.Value); err != nil {
		logrus.Error("Failed to create secret: ", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Secret created"})
	logrus.Info("Secret created for user: ", user.Username)
}

func UpdateSecret(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*auth.Claims)
	if !ok {
		logrus.Error("Failed to retrieve user claims from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]

	var req SecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.Error("Failed to decode update request: ", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if req.Name != name {
		logrus.Error("Name in URL does not match request body")
		http.Error(w, "Bad Request: Name mismatch", http.StatusBadRequest)
		return
	}

	if err := secrets.UpdateSecret(user.UserID, req.Name, req.Value); err != nil {
		logrus.Error("Failed to update secret: ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Secret updated"})
	logrus.Info("Secret updated for user: ", user.Username)
}

func DeleteSecret(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*auth.Claims)
	if !ok {
		logrus.Error("Failed to retrieve user claims from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]
	versionStr := vars["version"]

	version, err := strconv.Atoi(versionStr)
	if err != nil {
		logrus.Error("Invalid version format: ", err)
		http.Error(w, "Bad Request: Invalid version", http.StatusBadRequest)
		return
	}

	if err := secrets.DeleteSecret(user.UserID, name, version); err != nil {
		logrus.Error("Failed to delete secret: ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Secret deleted"})
	logrus.Info("Secret deleted for user: ", user.Username)
}

func ExportSecretsHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*auth.Claims)
	if !ok {
		logrus.Error("Failed to retrieve user claims from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	encryptedData, err := secrets.ExportSecrets(user.UserID)
	if err != nil {
		logrus.Error("Failed to export secrets: ", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"data": encryptedData})
	logrus.Info("Secrets exported for user: ", user.Username)
}

func GenerateKey(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*auth.Claims)
	if !ok {
		logrus.Error("Failed to retrieve user claims from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req KeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.Error("Failed to decode key request: ", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	key, err := keys.GenerateSSHKey(user.UserID, req.Name)
	if err != nil {
		logrus.Error("Failed to generate key: ", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(key)
	logrus.Info("Key generated for user: ", user.Username)
}

func GenerateCertificate(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*auth.Claims)
	if !ok {
		logrus.Error("Failed to retrieve user claims from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req KeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logrus.Error("Failed to decode certificate request: ", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	key, err := keys.GenerateCertificate(user.UserID, req.Name)
	if err != nil {
		logrus.Error("Failed to generate certificate: ", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(key)
	logrus.Info("Certificate generated for user: ", user.Username)
}

func RevokeKey(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*auth.Claims)
	if !ok {
		logrus.Error("Failed to retrieve user claims from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]

	if err := keys.RevokeKey(user.UserID, name); err != nil {
		logrus.Error("Failed to revoke key: ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Key revoked"})
	logrus.Info("Key revoked for user: ", user.Username)
}

func GetKey(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(*auth.Claims)
	if !ok {
		logrus.Error("Failed to retrieve user claims from context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	name := vars["name"]

	key, err := keys.GetKey(user.UserID, name)
	if err != nil {
		logrus.Error("Failed to get key: ", err)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(key)
	logrus.Info("Key retrieved for user: ", user.Username)
}
