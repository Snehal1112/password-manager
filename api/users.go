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
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"rocketvault/common"
	"rocketvault/internal/domain"
	userService "rocketvault/internal/services/users"
)

// CreateUserRequest represents the request structure for creating a user.
type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// UpdateUserRequest represents the request structure for updating a user.
type UpdateUserRequest struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Role     string `json:"role,omitempty"`
}

// UserResponse represents the response structure for user operations.
type UserResponse struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	Role       string `json:"role"`
	CreatedAt  string `json:"created_at"`
	TOTPSecret string `json:"totp_secret,omitempty"` // Only returned on creation
}

// ListUsersResponse represents the response structure for listing users.
type ListUsersResponse struct {
	Users []UserResponse `json:"users"`
	Total int            `json:"total"`
}

// LoginRequest represents the request structure for user login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

// LoginResponse represents the response structure for user login.
type LoginResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	Role         string `json:"role"`
}

// RefreshTokenRequest represents the request structure for token refresh.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshTokenResponse represents the response structure for token refresh.
type RefreshTokenResponse struct {
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	Role         string    `json:"role"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// SessionResponse represents a user session for API responses.
type SessionResponse struct {
	ID         string    `json:"id"`
	DeviceInfo string    `json:"device_info"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	CreatedAt  time.Time `json:"created_at"`
	Revoked    bool      `json:"revoked"`
}

// ListSessionsResponse represents the response structure for listing sessions.
type ListSessionsResponse struct {
	Sessions []SessionResponse `json:"sessions"`
	Total    int               `json:"total"`
}

// InitUsers initializes the routes for users management API.
// It sets up the following endpoints:
// - POST /users/login: Authenticate user and return JWT token (public).
// - POST /users/refresh: Refresh access token using refresh token (public).
// - GET /users/sessions: List current user's sessions (authenticated).
// - DELETE /users/sessions/{id}: Revoke a specific session (authenticated).
// - DELETE /users/sessions: Revoke all user sessions (authenticated).
// - POST /users: Create a new user (admin only).
// - GET /users: List all users (admin only).
// - GET /users/{id}: Get a specific user by ID.
// - PUT /users/{id}: Update a user (admin only or own profile).
// - DELETE /users/{id}: Delete a user (admin only).
//
// Parameters:
// - users (*mux.Router): The router to which the routes will be added.
func (api *API) InitUsers(users *mux.Router) {
	// Public endpoints - no authentication required
	users.Handle("/login", Handler(api.App, loginUser)).Methods("POST")
	users.Handle("/refresh", Handler(api.App, refreshToken)).Methods("POST")

	// Session management endpoints - authenticated
	users.Handle("/sessions", SessionRequired(api.App, listUserSessions)).Methods("GET")
	users.Handle("/sessions/{id:[A-Fa-f0-9-]+}", SessionRequired(api.App, revokeSession)).Methods("DELETE")
	users.Handle("/sessions", SessionRequired(api.App, revokeAllSessions)).Methods("DELETE")

	// Authenticated endpoints
	users.Handle("", SessionRequired(api.App, createUser)).Methods("POST")
	users.Handle("", SessionRequired(api.App, listUsers)).Methods("GET")
	users.Handle("/{id:[A-Fa-f0-9-]+}", SessionRequired(api.App, getUser)).Methods("GET")
	users.Handle("/{id:[A-Fa-f0-9-]+}", SessionRequired(api.App, updateUser)).Methods("PUT")
	users.Handle("/{id:[A-Fa-f0-9-]+}", SessionRequired(api.App, deleteUser)).Methods("DELETE")
}

// createUser handles the creation of a new user.
// It reads the user data from the request body, validates it, and attempts to create a new user.
// If successful, it returns the created user properties in the response with a status of 201 Created.
// Only users with admin role can create new users.
//
// Parameters:
//   - c: The context for the request, which includes error handling and application state.
//   - w: The HTTP response writer to send the response.
//   - r: The HTTP request containing the user data in the body.
//
// Possible errors:
//   - If the request body cannot be parsed into a CreateUserRequest model, it returns a 400 Bad Request error.
//   - If the user lacks admin privileges, it returns a 403 Forbidden error.
//   - If there is an error creating the user, it sets the error in the context and returns the appropriate status code.
func createUser(c *Context, w http.ResponseWriter, r *http.Request) {
	// Check admin privileges
	claims, ok := c.Claims["role"].(string)
	if !ok || claims != string(domain.RoleAdmin) {
		c.Err = common.NewAppError("createUser", "Forbidden: requires admin role", nil, "", http.StatusForbidden)
		return
	}

	// Parse request body
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("createUser", "Invalid request body", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate request
	if req.Username == "" || len(req.Username) < 3 || len(req.Username) > 50 {
		c.Err = common.NewAppError("createUser", "Invalid username: must be 3-50 characters", nil, "", http.StatusBadRequest)
		return
	}
	if req.Password == "" || len(req.Password) < 8 {
		c.Err = common.NewAppError("createUser", "Invalid password: must be at least 8 characters", nil, "", http.StatusBadRequest)
		return
	}
	validRoles := []string{domain.RoleAdmin, domain.RoleCryptoManager, domain.RoleCertificateManager, domain.RoleSecretsManager, domain.RoleUser}
	roleValid := false

	// Split role string by comma to support multiple roles
	requestedRoles := strings.Split(strings.TrimSpace(req.Role), ",")
	for _, requestedRole := range requestedRoles {
		requestedRole = strings.TrimSpace(requestedRole)
		if requestedRole == "" {
			continue
		}
		found := false
		for _, validRole := range validRoles {
			if requestedRole == validRole {
				found = true
				break
			}
		}
		if !found {
			roleValid = false
			break
		}
		roleValid = true
	}

	if !roleValid {
		c.Err = common.NewAppError("createUser", "Invalid role: must be one of secrets_manager, crypto_manager, certificate_manager, admin, user", nil, "", http.StatusBadRequest)
		return
	}

	userSvc := c.userSvc()
	if userSvc == nil {
		return
	}

	result, err := userSvc.CreateUser(r.Context(), userService.CreateUserRequest{
		Username:   req.Username,
		Password:   req.Password,
		Role:       req.Role,
		CallerRole: claims,
	})
	if err != nil {
		c.Err = common.NewAppError("createUser", "Failed to create user", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Prepare response
	response := UserResponse{
		ID:         result.UserID.String(),
		Username:   result.Username,
		Role:       result.Role,
		CreatedAt:  time.Now().Format(time.RFC3339), // Service doesn't return creation time
		TOTPSecret: result.TOTPSecret,               // Include TOTP secret on creation
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)

	// Log successful creation
	c.Logger.Printf("Admin %s created user %s with role %s", c.Claims["user_id"], result.Username, result.Role)
}

// listUsers handles the HTTP request to retrieve all users.
// It fetches all users from the database and returns them as a JSON response.
// Only users with admin role can list all users.
//
// Parameters:
//   - c: The context containing application-specific data and error handling.
//   - w: The HTTP response writer to send the response.
//   - r: The HTTP request.
func listUsers(c *Context, w http.ResponseWriter, r *http.Request) {
	// Check admin privileges
	claims, ok := c.Claims["role"].(string)
	if !ok || claims != string(domain.RoleAdmin) {
		c.Err = common.NewAppError("listUsers", "Forbidden: requires admin role", nil, "", http.StatusForbidden)
		return
	}

	// Parse query parameters
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50 // default limit
	offset := 0 // default offset

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	userSvc := c.userSvc()
	if userSvc == nil {
		return
	}

	users, err := userSvc.ListUsers(r.Context())
	if err != nil {
		c.Err = common.NewAppError("listUsers", "Failed to list users", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Apply pagination
	total := len(users)
	start := offset
	if start > total {
		start = total
	}

	end := start + limit
	if end > total {
		end = total
	}

	paginatedUsers := users[start:end]

	// Convert to response format
	userResponses := make([]UserResponse, len(paginatedUsers))
	for i, user := range paginatedUsers {
		userResponses[i] = UserResponse{
			ID:        user.ID.String(),
			Username:  user.Username,
			Role:      user.Role,
			CreatedAt: user.CreatedAt.Format(time.RFC3339),
		}
		// Note: User model doesn't have UpdatedAt field
	}

	response := ListUsersResponse{
		Users: userResponses,
		Total: total,
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getUser handles the HTTP request to retrieve a user by its ID.
// It extracts the user ID from the URL parameters, fetches the user
// information from the database, and writes the user data as a JSON response.
// Users can get their own profile or admins can get any user profile.
//
// Parameters:
//   - c: The context containing application-specific data and error handling.
//   - w: The HTTP response writer to send the response.
//   - r: The HTTP request containing the user ID in the URL parameters.
func getUser(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("getUser", "Invalid user ID", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Check permissions - admin can get any user, users can get their own profile
	currentUserID, _ := c.Claims["user_id"].(string)
	currentRole, _ := c.Claims["role"].(string)

	if currentRole != string(domain.RoleAdmin) && currentUserID != userID.String() {
		c.Err = common.NewAppError("getUser", "Forbidden: can only access own profile", nil, "", http.StatusForbidden)
		return
	}

	userSvc := c.userSvc()
	if userSvc == nil {
		return
	}

	user, err := userSvc.GetUser(r.Context(), userID)
	if err != nil {
		c.Err = common.NewAppError("getUser", "User not found", nil, err.Error(), http.StatusNotFound)
		return
	}

	// Prepare response
	response := UserResponse{
		ID:        user.ID.String(),
		Username:  user.Username,
		Role:      user.Role,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// updateUser handles the HTTP request to update a user by its ID.
// It extracts the user ID from the URL parameters, reads the update data
// from the request body, and updates the user in the database.
// Users can update their own profile or admins can update any user.
//
// Parameters:
//   - c: The context containing application-specific data and error handling.
//   - w: The HTTP response writer to send the response.
//   - r: The HTTP request containing the user ID and update data.
func updateUser(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("updateUser", "Invalid user ID", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Parse request body
	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("updateUser", "Invalid request body", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate request
	if req.Username != "" && (len(req.Username) < 3 || len(req.Username) > 50) {
		c.Err = common.NewAppError("updateUser", "Invalid username: must be 3-50 characters", nil, "", http.StatusBadRequest)
		return
	}
	if req.Password != "" && len(req.Password) < 8 {
		c.Err = common.NewAppError("updateUser", "Invalid password: must be at least 8 characters", nil, "", http.StatusBadRequest)
		return
	}
	if req.Role != "" {
		validRoles := []string{domain.RoleAdmin, domain.RoleCryptoManager, domain.RoleCertificateManager, domain.RoleSecretsManager, domain.RoleUser}
		roleValid := false

		// Split role string by comma to support multiple roles
		requestedRoles := strings.Split(strings.TrimSpace(req.Role), ",")
		for _, requestedRole := range requestedRoles {
			requestedRole = strings.TrimSpace(requestedRole)
			if requestedRole == "" {
				continue
			}
			found := false
			for _, validRole := range validRoles {
				if requestedRole == validRole {
					found = true
					break
				}
			}
			if !found {
				roleValid = false
				break
			}
			roleValid = true
		}

		if !roleValid {
			c.Err = common.NewAppError("updateUser", "Invalid role: must be one of secrets_manager, crypto_manager, certificate_manager, admin, user", nil, "", http.StatusBadRequest)
			return
		}
	}

	// Check permissions - admin can update any user, users can update their own profile (except role)
	currentUserID, _ := c.Claims["user_id"].(string)
	currentRole, _ := c.Claims["role"].(string)

	if currentRole != string(domain.RoleAdmin) {
		if currentUserID != userID.String() {
			c.Err = common.NewAppError("updateUser", "Forbidden: can only update own profile", nil, "", http.StatusForbidden)
			return
		}
		// Non-admin users cannot change their role
		if req.Role != "" {
			c.Err = common.NewAppError("updateUser", "Forbidden: cannot change own role", nil, "", http.StatusForbidden)
			return
		}
	}

	userSvc := c.userSvc()
	if userSvc == nil {
		return
	}

	// Convert to service request format with optional fields
	var usernamePtr, passwordPtr, rolePtr *string
	if req.Username != "" {
		usernamePtr = &req.Username
	}
	if req.Password != "" {
		passwordPtr = &req.Password
	}
	if req.Role != "" {
		rolePtr = &req.Role
	}

	// Update user using service
	if err := userSvc.UpdateUser(r.Context(), userService.UpdateUserRequest{
		UserID:   userID,
		Username: usernamePtr,
		Password: passwordPtr,
		Role:     rolePtr,
	}); err != nil {
		c.Err = common.NewAppError("updateUser", "Failed to update user", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get updated user for response
	user, err := userSvc.GetUser(r.Context(), userID)
	if err != nil {
		c.Err = common.NewAppError("updateUser", "Failed to get updated user", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Prepare response
	response := UserResponse{
		ID:        user.ID.String(),
		Username:  user.Username,
		Role:      user.Role,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	// Log successful update
	c.Logger.Printf("User %s updated user %s", currentUserID, userID.String())
}

// deleteUser handles the HTTP request to delete a user by its ID.
// It extracts the user ID from the URL parameters and deletes the user from the database.
// Only users with admin role can delete users.
//
// Parameters:
//   - c: The context containing application-specific data and error handling.
//   - w: The HTTP response writer to send the response.
//   - r: The HTTP request containing the user ID in the URL parameters.
func deleteUser(c *Context, w http.ResponseWriter, r *http.Request) {
	// Check admin privileges
	claims, ok := c.Claims["role"].(string)
	if !ok || claims != string(domain.RoleAdmin) {
		c.Err = common.NewAppError("deleteUser", "Forbidden: requires admin role", nil, "", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	userID, err := uuid.Parse(vars["id"])
	if err != nil {
		c.Err = common.NewAppError("deleteUser", "Invalid user ID", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Prevent self-deletion
	currentUserID, _ := c.Claims["user_id"].(string)
	if currentUserID == userID.String() {
		c.Err = common.NewAppError("deleteUser", "Cannot delete own account", nil, "", http.StatusBadRequest)
		return
	}

	userSvc := c.userSvc()
	if userSvc == nil {
		return
	}

	// Check if user exists by trying to get it
	if _, err := userSvc.GetUser(r.Context(), userID); err != nil {
		c.Err = common.NewAppError("deleteUser", "User not found", nil, err.Error(), http.StatusNotFound)
		return
	}

	// Delete user
	if err := userSvc.DeleteUser(r.Context(), userID); err != nil {
		c.Err = common.NewAppError("deleteUser", "Failed to delete user", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]any{
		"message": "User deleted successfully",
		"status":  "success",
	}
	json.NewEncoder(w).Encode(response)

	// Log successful deletion
	c.Logger.Printf("Admin %s deleted user %s", currentUserID, userID.String())
}

// loginUser handles user authentication and returns a JWT token.
// It validates username/password and TOTP code, then generates a JWT token for subsequent requests.
// This is a public endpoint that does not require prior authentication.
//
// Parameters:
//   - c: The context containing application-specific data and error handling.
//   - w: The HTTP response writer to send the response.
//   - r: The HTTP request containing login credentials.
func loginUser(c *Context, w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("loginUser", "Invalid request body", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate request
	if req.Username == "" || req.Password == "" || req.TOTPCode == "" {
		c.Err = common.NewAppError("loginUser", "Username, password, and TOTP code are required", nil, "", http.StatusBadRequest)
		return
	}

	// Use service container for authentication
	authSvc := c.authSvc()
	if authSvc == nil {
		return
	}
	result, err := authSvc.AuthenticateUser(r.Context(), req.Username, req.Password, req.TOTPCode)
	if err != nil {
		c.Logger.Printf("Login failed for user %s: %v", req.Username, err)
		c.Err = common.NewAppError("loginUser", "Authentication failed", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	// Prepare response
	response := LoginResponse{
		Token:        result.Token,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID.String(),
		Username:     result.Username,
		Role:         result.Role,
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	// Log successful login
	c.Logger.Printf("User %s (ID: %s) logged in successfully with role %s",
		result.Username, result.UserID.String(), result.Role)
}

// refreshToken handles the refresh of an access token using a refresh token.
// It validates the refresh token and returns a new access token and optionally
// a new refresh token for enhanced security.
//
// Parameters:
//   - c: The context containing application-specific data and error handling.
//   - w: The HTTP response writer to send the response.
//   - r: The HTTP request containing the refresh token in the body.
//
// Possible errors:
//   - If the request body cannot be parsed, it returns a 400 Bad Request error.
//   - If the refresh token is invalid or expired, it returns a 401 Unauthorized error.
//   - If there is an error refreshing the token, it sets the error in the context and returns the appropriate status code.
func refreshToken(c *Context, w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		c.Err = common.NewAppError("refreshToken", "Invalid request body", nil, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate request
	if req.RefreshToken == "" {
		c.Err = common.NewAppError("refreshToken", "Refresh token is required", nil, "", http.StatusBadRequest)
		return
	}

	// Use service container for token refresh
	authSvc := c.authSvc()
	if authSvc == nil {
		return
	}
	result, err := authSvc.RefreshAccessToken(r.Context(), req.RefreshToken)
	if err != nil {
		c.Logger.Printf("Token refresh failed: %v", err)
		c.Err = common.NewAppError("refreshToken", "Token refresh failed", nil, err.Error(), http.StatusUnauthorized)
		return
	}

	// Prepare response
	response := RefreshTokenResponse{
		Token:        result.Token,
		RefreshToken: result.RefreshToken,
		UserID:       result.UserID.String(),
		Username:     result.Username,
		Role:         result.Role,
		ExpiresAt:    result.ExpiresAt,
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	// Log successful token refresh
	c.Logger.Printf("Access token refreshed for user %s (ID: %s)",
		result.Username, result.UserID.String())
}

// listUserSessions handles the HTTP request to list all sessions for the current user.
// It retrieves all active sessions for the authenticated user and returns them as a JSON response.
//
// Parameters:
//   - c: The context containing application-specific data and error handling.
//   - w: The HTTP response writer to send the response.
//   - r: The HTTP request.
func listUserSessions(c *Context, w http.ResponseWriter, r *http.Request) {
	// Get current user ID from claims
	currentUserID, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("listUserSessions", "Invalid user ID in claims", nil, "", http.StatusInternalServerError)
		return
	}

	userID, err := uuid.Parse(currentUserID)
	if err != nil {
		c.Err = common.NewAppError("listUserSessions", "Invalid user ID format", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Use service container for session listing
	sessionRepo := c.sessionRepo()
	if sessionRepo == nil {
		return
	}
	sessions, err := sessionRepo.GetActiveSessionsByUserID(r.Context(), userID)
	if err != nil {
		c.Err = common.NewAppError("listUserSessions", "Failed to list sessions", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert to response format
	sessionResponses := make([]SessionResponse, len(sessions))
	for i, session := range sessions {
		sessionResponses[i] = SessionResponse{
			ID:         session.ID.String(),
			DeviceInfo: session.DeviceInfo,
			IPAddress:  session.IPAddress,
			UserAgent:  session.UserAgent,
			ExpiresAt:  session.ExpiresAt,
			LastUsedAt: session.LastUsedAt,
			CreatedAt:  session.CreatedAt,
			Revoked:    session.Revoked,
		}
	}

	response := ListSessionsResponse{
		Sessions: sessionResponses,
		Total:    len(sessionResponses),
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// revokeSession handles the HTTP request to revoke a specific session.
// It extracts the session ID from the URL parameters and revokes the session.
// Users can revoke their own sessions.
//
// Parameters:
//   - c: The context containing application-specific data and error handling.
//   - w: The HTTP response writer to send the response.
//   - r: The HTTP request containing the session ID in the URL parameters.
func revokeSession(c *Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["id"]

	// Get current user ID from claims
	currentUserID, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("revokeSession", "Invalid user ID in claims", nil, "", http.StatusInternalServerError)
		return
	}

	// Use service container for session revocation
	authSvc := c.authSvc()
	if authSvc == nil {
		return
	}
	if err := authSvc.RevokeSession(r.Context(), sessionID, "User requested revocation"); err != nil {
		c.Err = common.NewAppError("revokeSession", "Failed to revoke session", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	response := map[string]any{
		"message": "Session revoked successfully",
		"status":  "success",
	}
	json.NewEncoder(w).Encode(response)

	// Log successful revocation
	c.Logger.Printf("User %s revoked session %s", currentUserID, sessionID)
}

// revokeAllSessions handles the HTTP request to revoke all sessions for the current user.
// It revokes all active sessions for the authenticated user.
//
// Parameters:
//   - c: The context containing application-specific data and error handling.
//   - w: The HTTP response writer to send the response.
//   - r: The HTTP request.
func revokeAllSessions(c *Context, w http.ResponseWriter, r *http.Request) {
	// Get current user ID from claims
	currentUserID, ok := c.Claims["user_id"].(string)
	if !ok {
		c.Err = common.NewAppError("revokeAllSessions", "Invalid user ID in claims", nil, "", http.StatusInternalServerError)
		return
	}

	userID, err := uuid.Parse(currentUserID)
	if err != nil {
		c.Err = common.NewAppError("revokeAllSessions", "Invalid user ID format", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Use service container for revoking all sessions
	authSvc := c.authSvc()
	if authSvc == nil {
		return
	}
	if err := authSvc.RevokeAllUserSessions(r.Context(), userID, "User requested revocation of all sessions"); err != nil {
		c.Err = common.NewAppError("revokeAllSessions", "Failed to revoke all sessions", nil, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	response := map[string]any{
		"message": "All sessions revoked successfully",
		"status":  "success",
	}
	json.NewEncoder(w).Encode(response)

	// Log successful revocation
	c.Logger.Printf("User %s revoked all sessions", currentUserID)
}
