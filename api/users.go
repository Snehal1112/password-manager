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
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"password-manager/common"
	"password-manager/internal/domain"
	userService "password-manager/internal/services/users"
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

// InitUsers initializes the routes for users management API.
// It sets up the following endpoints:
// - POST /users: Create a new user (admin only).
// - GET /users: List all users (admin only).
// - GET /users/{id}: Get a specific user by ID.
// - PUT /users/{id}: Update a user (admin only or own profile).
// - DELETE /users/{id}: Delete a user (admin only).
//
// Parameters:
// - users (*mux.Router): The router to which the routes will be added.
func (api *API) InitUsers(users *mux.Router) {
	users.Handle("", ApiSessionRequired(api.App, createUser)).Methods("POST")
	users.Handle("", ApiSessionRequired(api.App, listUsers)).Methods("GET")
	users.Handle("/{id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, getUser)).Methods("GET")
	users.Handle("/{id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, updateUser)).Methods("PUT")
	users.Handle("/{id:[A-Fa-f0-9-]+}", ApiSessionRequired(api.App, deleteUser)).Methods("DELETE")
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
	validRoles := []string{"secrets_manager", "crypto_manager", "certificate_manager", "admin"}
	roleValid := false
	for _, role := range validRoles {
		if req.Role == role {
			roleValid = true
			break
		}
	}
	if !roleValid {
		c.Err = common.NewAppError("createUser", "Invalid role: must be one of secrets_manager, crypto_manager, certificate_manager, admin", nil, "", http.StatusBadRequest)
		return
	}

	// Use service container for user creation
	if c.App.ServiceContainer == nil {
		c.Err = common.NewAppError("createUser", "Service container not available", nil, "", http.StatusInternalServerError)
		return
	}

	userSvc := c.App.ServiceContainer.GetUserService()
	result, err := userSvc.CreateUser(r.Context(), userService.CreateUserRequest{
		Username: req.Username,
		Password: req.Password,
		Role:     req.Role,
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
		TOTPSecret: result.TOTPSecret, // Include TOTP secret on creation
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)

	// Log successful creation
	c.Logger.Printf("Admin %s created user %s with role %s",
		c.Claims["user_id"], result.Username, result.Role)
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

	// Use service container for user listing
	if c.App.ServiceContainer == nil {
		c.Err = common.NewAppError("listUsers", "Service container not available", nil, "", http.StatusInternalServerError)
		return
	}

	userSvc := c.App.ServiceContainer.GetUserService()
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

	// Use service container for user retrieval
	if c.App.ServiceContainer == nil {
		c.Err = common.NewAppError("getUser", "Service container not available", nil, "", http.StatusInternalServerError)
		return
	}

	userSvc := c.App.ServiceContainer.GetUserService()
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
		validRoles := []string{"secrets_manager", "crypto_manager", "certificate_manager", "admin"}
		roleValid := false
		for _, role := range validRoles {
			if req.Role == role {
				roleValid = true
				break
			}
		}
		if !roleValid {
			c.Err = common.NewAppError("updateUser", "Invalid role: must be one of secrets_manager, crypto_manager, certificate_manager, admin", nil, "", http.StatusBadRequest)
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

	// Use service container for user update
	if c.App.ServiceContainer == nil {
		c.Err = common.NewAppError("updateUser", "Service container not available", nil, "", http.StatusInternalServerError)
		return
	}

	userSvc := c.App.ServiceContainer.GetUserService()

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

	// Use service container for user deletion
	if c.App.ServiceContainer == nil {
		c.Err = common.NewAppError("deleteUser", "Service container not available", nil, "", http.StatusInternalServerError)
		return
	}

	userSvc := c.App.ServiceContainer.GetUserService()

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
	response := map[string]interface{}{
		"message": "User deleted successfully",
		"status":  "success",
	}
	json.NewEncoder(w).Encode(response)

	// Log successful deletion
	c.Logger.Printf("Admin %s deleted user %s", currentUserID, userID.String())
}